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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/NTTS-Innovation/samurai-go/pkg/credentials"
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

func sendRequest(body []byte, credentials credentials.APICredentials) ([]byte, error) {
	HTTPClient := &http.Client{
		Timeout: time.Second * 10,
	}
	defer HTTPClient.CloseIdleConnections()

	request, err := http.NewRequest("POST", credentials.URL+"/cts/payload", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("x-api-key", credentials.APIKey)
	request.Header.Add("device_id", credentials.DeviceId)
	request.Header.Add("passkey", credentials.Passkey)

	response, err := HTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 {
		err := fmt.Errorf("status code: %d\n%v", response.StatusCode, string(bodyBytes))
		return nil, err
	}

	return bodyBytes, nil
}

func getSignedURL(partData sasResult, part int, credentials credentials.APICredentials, settings Settings) (signedURLMessage, error) {
	var result signedURLMessage
	body, err := json.Marshal(signedURL{"GET_SIGNED_URL", partData.Key, partData.UploadId, part})
	if err != nil {
		return result, err
	}

	bodyBytes, err := sendRequest(body, credentials)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func completeUpload(partData sasResult, parts []parts, credentials credentials.APICredentials, settings Settings) (completeMultipartUploadMessage, error) {
	var result completeMultipartUploadMessage
	body, err := json.Marshal(completeMultipartUpload{"COMPLETE_MULTIPART_UPLOAD", partData.Key, partData.UploadId, parts})
	if err != nil {
		return result, err
	}

	bodyBytes, err := sendRequest(body, credentials)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func abortMultipartUpload(partData sasResult, credentials credentials.APICredentials, settings Settings) (abortMultipartUploadMessage, error) {
	var result abortMultipartUploadMessage
	body, err := json.Marshal(abortedMultipartUpload{"ABORT_MULTIPART_UPLOAD", partData.Key, partData.UploadId})
	if err != nil {
		return result, err
	}

	bodyBytes, err := sendRequest(body, credentials)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func partsTransmitter(ChunkChan <-chan transmitterPayload, control control, threadNr int) {
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
			HTTPClient := &http.Client{Timeout: time.Second * 600}

			request, err := http.NewRequest(http.MethodPut, part.signed_url, part.chunk)
			if err != nil {
				log.Errorln(err)
				HTTPClient.CloseIdleConnections()
				continue
			}
			response, err := HTTPClient.Do(request)
			if err != nil {
				log.Errorln(err)
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
