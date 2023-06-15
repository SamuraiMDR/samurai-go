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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/NTTS-Innovation/samurai-go/pkg/credentials"
	"github.com/inhies/go-bytesize"
	log "github.com/sirupsen/logrus"
)

type Settings struct {
	allowInsecureTLS bool   `yaml:"insecure"`
	Debug            bool   `yaml:"debug"`
	Profile          string `yaml:"profile"`
}

type control struct {
	EndpointWG       *sync.WaitGroup
	StopChan         chan struct{}
	PartsChan        chan interface{}
	HaltTransmitters bool
}

var errUnknownPayload = errors.New("unknown payload")

// var errCorruptPayload = errors.New("corrupt payload")

// var types = []string{"docker", "syslog", "pdns", "bouncer", "assets", "logfiles", "contrive_bouncer"} // Add new types here, same slice is used for filter validation
type sas struct {
	Payload string `json:"payload"`
	Profile string `json:"profile"`
}

type sasResult struct {
	SASURL   string `json:"sas_url"`
	Type     string `json:"profile_type"`
	Key      string `json:"key"`
	UploadId string `json:"upload_id"`
}

//func getType(filename string) string {
//	dir := filepath.Dir(filename)
//	return filepath.Base(dir)
//}

func getSAS(payload string, credentials credentials.APICredentials, settings Settings) (sasResult, error) {
	var result sasResult

	body, err := json.Marshal(sas{payload, settings.Profile})
	if err != nil {
		return result, err
	}
	log.Infof(string(body))
	HTTPClient := &http.Client{
		Timeout: time.Second * 10,
	}

	defer HTTPClient.CloseIdleConnections()
	request, err := http.NewRequest("POST", credentials.URL+"/cts/payload", bytes.NewBuffer(body))
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
		} else if response.StatusCode == 415 {
			return result, errUnknownPayload
			//		} else if response.StatusCode == 406 {
			//			return result, ErrCorruptPayload
		} else {
			err := fmt.Errorf("status code: %d, Body: %v", response.StatusCode, string(bodyBytes))
			return result, err
		}
	}
	defer response.Body.Close()
	return result, nil
}

func SendFile(filename string, payloadType string, credentials credentials.APICredentials, settings Settings) error {
	if settings.Profile == "" {
		settings.Profile = "default"
	}

	if settings.allowInsecureTLS {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: settings.allowInsecureTLS}
	}

	// payloadType := getType(filename)
	result, err := getSAS(payloadType, credentials, settings)
	if err != nil {
		return err
	}
	if err == errUnknownPayload {
		log.Warnf("Uploading file %v aborted since payload %v is not supported", filename, payloadType)
		return err
	} else if err != nil {
		return fmt.Errorf("unknown error from backend: %v", err)
	}
	if result.Type == "azure" {
		uploadToAzureSAS(filename, result.SASURL, settings)
	} else if result.Type == "s3" {
		var completeMultipartUpload CompleteMultipartUpload
		var control = control{
			EndpointWG:       &sync.WaitGroup{},
			StopChan:         make(chan struct{}),
			PartsChan:        make(chan interface{}),
			HaltTransmitters: false,
		}
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
		log.Infof("Uploading file %v, total %v", filename, bytesize.ByteSize(fileSize).String())

		buffer := make([]byte, fileSize)
		_, err = file.Read(buffer)
		if err != nil {
			return err
		}

		var start, currentSize int
		var remaining = int(fileSize)
		var partNum = 1
		completeMultipartUpload.EventType = payloadType
		completeMultipartUpload.Key = result.Key
		completeMultipartUpload.UploadId = result.UploadId

		// Create channel for chunks to handle
		ChunkChan := make(chan TransmitterPayload, PartsTransmitterWorkers)
		// Start workers
		for i := 0; i < PartsTransmitterWorkers; i++ {
			//log.Infoln("Starting transmitter worker " + strconv.Itoa(i))
			go partsTransmitter(ChunkChan, control, i)
		}
		// Collect data from completed multiparts
		go func() {
			for {
				select {
				case partsOrErr := <-control.PartsChan:
					if partsOrErr == nil {
						control.EndpointWG.Done()
					} else {
						log.Debugf("  ... transfer part %v completed", partsOrErr.(Parts).PartNumber)
						completeMultipartUpload.Parts = append(completeMultipartUpload.Parts, partsOrErr.(Parts))
						control.EndpointWG.Done()
					}
				case <-control.StopChan:
					// Job is done, exit function
					return
				}
			}
		}()

		for start = 0; remaining > 0; start += PartSize {
			for {
				if control.HaltTransmitters {
					break
				}
				if len(ChunkChan) < PartsTransmitterWorkers {
					if remaining < PartSize {
						currentSize = remaining
					} else {
						currentSize = PartSize
					}
					signedURL, err := getSignedURL(result, partNum, credentials, settings)
					if err != nil {
						return err
					}
					control.EndpointWG.Add(1)
					remaining -= currentSize
					ChunkChan <- TransmitterPayload{signedURL.SignedURL, bytes.NewReader(buffer[start : start+currentSize]), partNum, remaining}
					partNum++
					break
				} else {
					time.Sleep(100 * time.Millisecond)
				}
			}

		}
		control.EndpointWG.Wait()
		close(control.StopChan)
		if control.HaltTransmitters {
			result, err := abortMultipartUpload(result, credentials, settings)
			if err != nil {
				return err
			} else {
				err := fmt.Errorf(result.Message)
				return err
			}
		} else {
			sort.SliceStable(completeMultipartUpload.Parts, func(i, j int) bool {
				return completeMultipartUpload.Parts[i].PartNumber < completeMultipartUpload.Parts[j].PartNumber
			})
			result, err := completeUpload(result, completeMultipartUpload.Parts, credentials, settings)
			if err != nil {
				return err
			} else {
				log.Debugln(result.Message)
				return nil
			}
		}

	} else {
		return fmt.Errorf("unknown result type: %v", result.Type)
	}

	return nil
}
