/*
 * NTT Security Holdings Go Library for Samurai
 * Copyright 2023 NTT Security Holdings
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package transmitter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/inhies/go-bytesize"
	log "github.com/sirupsen/logrus"
)

// partSize is the size of every part but the last. S3 requires at least
// 5 MiB for all parts but the last.
var partSize int64 = 100 * 1024 * 1024
var partsTransmitterWorkers = 3
var maxRetry = 3

// partRetryDelay is multiplied by the attempt number between part retries.
var partRetryDelay = time.Second

// abortTimeout bounds ABORT_MULTIPART_UPLOAD, which runs even when the
// caller's context is already done.
var abortTimeout = 30 * time.Second

type parts struct {
	ETag       string `json:"ETag"`
	PartNumber int    `json:"PartNumber"`
}

type completeMultipartUpload struct {
	EventType string  `json:"event_type"`
	Key       string  `json:"key"`
	UploadId  string  `json:"upload_id"`
	Parts     []parts `json:"parts"`
}

type completeMultipartUploadMessage struct {
	Message string `json:"Message"`
}

type abortedMultipartUpload struct {
	EventType string `json:"event_type"`
	Key       string `json:"key"`
	UploadId  string `json:"upload_id"`
}

type abortMultipartUploadMessage struct {
	Message string `json:"Message"`
}

type signedURL struct {
	EventType string `json:"event_type"`
	Key       string `json:"key"`
	UploadId  string `json:"upload_id"`
	Part      int    `json:"part"`
}

type signedURLMessage struct {
	SignedURL string `json:"signed_url"`
}

func (client Client) sendRequest(ctx context.Context, body []byte) ([]byte, error) {
	credentials := client.credentials
	HTTPClient := client.httpClient(time.Second * 10)
	defer HTTPClient.CloseIdleConnections()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, credentials.URL+"/cts/payload", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	setAPIHeaders(request, credentials)

	response, err := HTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	bodyBytes, truncated, err := readResponseBody(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 {
		err := fmt.Errorf("status code: %d, body: %s", response.StatusCode, errorBody(bodyBytes))
		return nil, err
	}
	if truncated {
		return nil, errResponseTooLarge
	}

	return bodyBytes, nil
}

func (client Client) getSignedURL(ctx context.Context, partData sasResult, part int) (signedURLMessage, error) {
	var result signedURLMessage
	body, err := json.Marshal(signedURL{"GET_SIGNED_URL", partData.Key, partData.UploadId, part})
	if err != nil {
		return result, err
	}

	bodyBytes, err := client.sendRequest(ctx, body)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func (client Client) completeUpload(ctx context.Context, partData sasResult, parts []parts) (completeMultipartUploadMessage, error) {
	var result completeMultipartUploadMessage
	body, err := json.Marshal(completeMultipartUpload{"COMPLETE_MULTIPART_UPLOAD", partData.Key, partData.UploadId, parts})
	if err != nil {
		return result, err
	}

	bodyBytes, err := client.sendRequest(ctx, body)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func (client Client) abortMultipartUpload(ctx context.Context, partData sasResult) (abortMultipartUploadMessage, error) {
	var result abortMultipartUploadMessage
	body, err := json.Marshal(abortedMultipartUpload{"ABORT_MULTIPART_UPLOAD", partData.Key, partData.UploadId})
	if err != nil {
		return result, err
	}

	bodyBytes, err := client.sendRequest(ctx, body)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

// uploadToS3 uploads filename as an S3 multipart upload. Parts are streamed
// from disk by partsTransmitterWorkers workers. If any part fails, or ctx is
// done, the remaining work stops and the multipart upload is aborted so no
// orphaned parts are left behind. It only completes when every part has
// succeeded.
func (client Client) uploadToS3(ctx context.Context, filename string, sr sasResult) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := stat.Size()
	numParts := int((fileSize + partSize - 1) / partSize)
	if numParts == 0 {
		// An empty file is still uploaded, as a single empty part.
		numParts = 1
	}
	log.Infof("Uploading file %v, total %v in %v parts", filename, bytesize.ByteSize(fileSize).String(), numParts)

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	// Each worker writes only its own part's slot, and wg.Wait orders
	// those writes before the reads below.
	uploaded := make([]parts, numParts)
	partNums := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < partsTransmitterWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for partNum := range partNums {
				etag, err := client.uploadPart(ctx, file, sr, partNum, fileSize)
				if err != nil {
					cancel(err)
					continue
				}
				uploaded[partNum-1] = parts{ETag: etag, PartNumber: partNum}
			}
		}()
	}

feed:
	for partNum := 1; partNum <= numParts; partNum++ {
		select {
		case partNums <- partNum:
		case <-ctx.Done():
			break feed
		}
	}
	close(partNums)
	wg.Wait()

	if err := context.Cause(ctx); err != nil {
		return client.abortS3Upload(ctx, filename, sr, err)
	}
	for _, part := range uploaded {
		if part.ETag == "" {
			return client.abortS3Upload(ctx, filename, sr, fmt.Errorf("part %v has no ETag", part.PartNumber))
		}
	}

	result, err := client.completeUpload(ctx, sr, uploaded)
	if err != nil {
		return fmt.Errorf("could not complete upload of %v: %w", filename, err)
	}
	log.Debugln(result.Message)
	return nil
}

// abortS3Upload aborts the multipart upload after cause. It uses its own
// timeout since ctx may be the reason the upload stopped.
func (client Client) abortS3Upload(ctx context.Context, filename string, sr sasResult, cause error) error {
	uploadErr := fmt.Errorf("upload of %v failed: %w", filename, cause)
	abortCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), abortTimeout)
	defer cancel()
	result, err := client.abortMultipartUpload(abortCtx, sr)
	if err != nil {
		return errors.Join(uploadErr, fmt.Errorf("could not abort multipart upload: %w", err))
	}
	log.Debugf("Aborted upload of %v: %v", filename, result.Message)
	return uploadErr
}

// uploadPart uploads one part, retrying up to maxRetry times, and returns its
// ETag. Every attempt gets a fresh signed URL and a fresh reader over the
// file, so a retry always sends the whole part.
func (client Client) uploadPart(ctx context.Context, file *os.File, sr sasResult, partNum int, fileSize int64) (string, error) {
	offset := int64(partNum-1) * partSize
	length := min(partSize, fileSize-offset)
	var lastErr error
	for attempt := 1; attempt <= maxRetry; attempt++ {
		if attempt == 1 {
			log.Debugf("  ... transfer part %v started, %v", partNum, bytesize.ByteSize(length).String())
		} else {
			log.Warnf("  ... resending part %v, try %v of %v", partNum, attempt, maxRetry)
			select {
			case <-time.After(partRetryDelay * time.Duration(attempt-1)):
			case <-ctx.Done():
				return "", context.Cause(ctx)
			}
		}
		etag, err := client.putPart(ctx, file, sr, partNum, offset, length)
		if err == nil {
			log.Debugf("  ... transfer part %v completed", partNum)
			return etag, nil
		}
		if ctx.Err() != nil {
			return "", context.Cause(ctx)
		}
		log.Errorf("Part %v, try %v of %v failed: %v", partNum, attempt, maxRetry, err)
		lastErr = err
	}
	return "", fmt.Errorf("part %v failed after %v tries: %w", partNum, maxRetry, lastErr)
}

// putPart makes a single attempt at uploading a part.
func (client Client) putPart(ctx context.Context, file *os.File, sr sasResult, partNum int, offset int64, length int64) (string, error) {
	signed, err := client.getSignedURL(ctx, sr, partNum)
	if err != nil {
		return "", fmt.Errorf("could not get signed url: %w", err)
	}

	var body io.Reader = http.NoBody
	if length > 0 {
		body = io.NewSectionReader(file, offset, length)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, signed.SignedURL, body)
	if err != nil {
		return "", redactError(err, signed.SignedURL)
	}
	// S3 needs the length up front. It cannot be inferred from a SectionReader.
	request.ContentLength = length

	response, err := client.httpClient(time.Second * 600).Do(request)
	if err != nil {
		return "", redactError(err, signed.SignedURL)
	}
	defer response.Body.Close()
	responseBody, _, err := readResponseBody(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("status code: %d, body: %s", response.StatusCode, errorBody(responseBody))
	}
	etag := response.Header.Get("ETag")
	if etag == "" {
		return "", errors.New("response has no ETag")
	}
	return etag, nil
}
