package transmitter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/inhies/go-bytesize"
	log "github.com/sirupsen/logrus"
)

var PartSize = 100 * 1024 * 1024 // 5 Mb (5 Mb is AWS S3 minimum value)
var PartsTransmitterWorkers = 3
var MaxRetry = 3

type Parts struct {
	ETag       string `json:"ETag"`
	PartNumber int    `json:"PartNumber"`
}

type CreateMultipartUpload struct {
	Payload   string `json:"payload"`
	EventType string `json:"event_type"`
}

type CompleteMultipartUpload struct {
	EventType string  `json:"event_type"`
	Key       string  `json:"key"`
	UploadId  string  `json:"upload_id"`
	Parts     []Parts `json:"parts"`
}

type CompleteMultipartUploadMessage struct {
	Message string `json:"Message"`
}

type AbortMultipartUpload struct {
	EventType string `json:"event_type"`
	Key       string `json:"key"`
	UploadId  string `json:"upload_id"`
}

type AbortMultipartUploadMessage struct {
	Message string `json:"Message"`
}

type GetSignedURL struct {
	EventType string `json:"event_type"`
	Key       string `json:"key"`
	UploadId  string `json:"upload_id"`
	Part      int    `json:"part"`
}

type GetSignedURLMessage struct {
	SignedURL string `json:"signed_url"`
}

type TransmitterPayload struct {
	signed_url string
	chunk      io.Reader
	partNum    int
	remaining  int
}

func getSignedURL(partData sasResult, part int, settings Settings, credentials Credentials) (GetSignedURLMessage, error) {
	var result GetSignedURLMessage
	body, err := json.Marshal(GetSignedURL{"GET_SIGNED_URL", partData.Key, partData.UploadId, part})
	if err != nil {
		return result, err
	}
	HTTPClient := &http.Client{
		Timeout: time.Second * 10,
	}

	defer HTTPClient.CloseIdleConnections()
	request, err := http.NewRequest("POST", settings.URL+"/cts/payload", bytes.NewBuffer(body))
	if err != nil {
		return result, err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("x-api-key", credentials.APIKey)
	request.Header.Add("device_id", credentials.DeviceId)
	request.Header.Add("passkey", credentials.Passkey)

	response, err := HTTPClient.Do(request)
	if err != nil {
		return result, err
	} else {
		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil {
			log.Errorln(err)
		}
		if response.StatusCode == 200 {
			err := json.Unmarshal(bodyBytes, &result)
			if err != nil {
				log.Errorln(err)
			}
		} else {
			err := fmt.Errorf("status code: %d\n%v", response.StatusCode, string(bodyBytes))
			return result, err
		}
	}
	defer response.Body.Close()
	return result, nil
}

func completeUpload(partData sasResult, parts []Parts, settings Settings, credentials Credentials) (CompleteMultipartUploadMessage, error) {
	var result CompleteMultipartUploadMessage
	body, err := json.Marshal(CompleteMultipartUpload{"COMPLETE_MULTIPART_UPLOAD", partData.Key, partData.UploadId, parts})
	if err != nil {
		return result, err
	}
	HTTPClient := &http.Client{
		Timeout: time.Second * 10,
	}

	defer HTTPClient.CloseIdleConnections()
	request, err := http.NewRequest("POST", settings.URL+"/cts/payload", bytes.NewBuffer(body))
	if err != nil {
		return result, err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("x-api-key", credentials.APIKey)
	request.Header.Add("device_id", credentials.DeviceId)
	request.Header.Add("passkey", credentials.Passkey)

	response, err := HTTPClient.Do(request)
	if err != nil {
		return result, err
	} else {
		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil {
			log.Errorln(err)
		}
		if response.StatusCode == 200 {
			err := json.Unmarshal(bodyBytes, &result)
			if err != nil {
				log.Errorln(err)
			}
		} else {
			err := fmt.Errorf("status code: %d\n%v", response.StatusCode, string(bodyBytes))
			return result, err
		}
	}
	defer response.Body.Close()
	return result, nil
}

func abortMultipartUpload(partData sasResult, settings Settings, credentials Credentials) (AbortMultipartUploadMessage, error) {
	var result AbortMultipartUploadMessage
	body, err := json.Marshal(AbortMultipartUpload{"ABORT_MULTIPART_UPLOAD", partData.Key, partData.UploadId})
	if err != nil {
		return result, err
	}
	HTTPClient := &http.Client{
		Timeout: time.Second * 10,
	}

	defer HTTPClient.CloseIdleConnections()
	request, err := http.NewRequest("POST", settings.URL+"/cts/payload", bytes.NewBuffer(body))
	if err != nil {
		return result, err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("x-api-key", credentials.APIKey)
	request.Header.Add("device_id", credentials.DeviceId)
	request.Header.Add("passkey", credentials.Passkey)

	response, err := HTTPClient.Do(request)
	if err != nil {
		return result, err
	} else {
		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil {
			log.Errorln(err)
		}
		if response.StatusCode == 200 {
			err := json.Unmarshal(bodyBytes, &result)
			if err != nil {
				log.Errorln(err)
			}
		} else {
			err := fmt.Errorf("status code: %d\n%v", response.StatusCode, string(bodyBytes))
			return result, err
		}
	}
	defer response.Body.Close()
	return result, nil
}

func partsTransmitter(ChunkChan <-chan TransmitterPayload, control control, threadNr int) {
	for part := range ChunkChan {
		for i := 0; i <= MaxRetry; i++ {
			if control.HaltTransmitters {
				control.PartsChan <- nil
				return
			}
			if i == 0 {
				log.Debugf("  ... transfer part %v started, %v remaning", part.partNum, bytesize.ByteSize(part.remaining).String())
			} else {
				log.Warnf("  ... resending part %v, try %v \n", part.partNum, i)
			}
			parts := Parts{}
			HTTPClient := &http.Client{Timeout: time.Second * 600}

			request, err := http.NewRequest(http.MethodPut, part.signed_url, part.chunk)
			if err != nil {
				log.Errorln(err)
				HTTPClient.CloseIdleConnections()
				if i >= MaxRetry {
					log.Errorf("Aborting upload due to max retries for part %v has been reached", part.partNum)
					control.HaltTransmitters = true
				}
			} else {
				response, err := HTTPClient.Do(request)
				if err != nil {
					log.Errorln(err)
					HTTPClient.CloseIdleConnections()
					if i >= MaxRetry {
						log.Errorf("Aborting upload due to max retries for part %v has been reached", part.partNum)
						control.HaltTransmitters = true
					}
				} else {
					parts.ETag = response.Header.Get("ETag")
					parts.PartNumber = part.partNum
					control.PartsChan <- parts
					HTTPClient.CloseIdleConnections()
					break
				}
			}
		}
	}
}
