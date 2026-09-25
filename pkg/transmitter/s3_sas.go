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
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/inhies/go-bytesize"
	log "github.com/sirupsen/logrus"
)

var partSize = 100 * 1024 * 1024 // 5 Mb (5 Mb is AWS S3 minimum value)
var partsTransmitterWorkers = 3
var maxRetry = 3

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

type transmitterPayload struct {
	signed_url string
	chunk      io.Reader
	partNum    int
	remaining  int
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

func (client Client) partsTransmitter(ctx context.Context, ChunkChan <-chan transmitterPayload, control control) {
	for part := range ChunkChan {
		for i := 0; i <= maxRetry; i++ {
			if i >= maxRetry {
				log.Errorf("Aborting upload due to max retries for part %v has been reached", part.partNum)
				control.HaltTransmitters = true
			}

			if control.HaltTransmitters {
				control.PartsChan <- nil
				return
			}
			if i == 0 {
				log.Debugf("  ... transfer part %v started, %v remaning", part.partNum, bytesize.ByteSize(part.remaining).String())
			} else {
				log.Warnf("  ... resending part %v, try %v \n", part.partNum, i)
			}
			parts := parts{}
			HTTPClient := client.httpClient(time.Second * 600)

			request, err := http.NewRequestWithContext(ctx, http.MethodPut, part.signed_url, part.chunk)
			if err != nil {
				log.Errorln(redactError(err, part.signed_url))
				HTTPClient.CloseIdleConnections()
				continue
			}
			response, err := HTTPClient.Do(request)
			if err != nil {
				log.Errorln(redactError(err, part.signed_url))
				HTTPClient.CloseIdleConnections()
				continue
			}
			parts.ETag = response.Header.Get("ETag")
			parts.PartNumber = part.partNum
			control.PartsChan <- parts
			break
		}
	}
}
