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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SamuraiMDR/samurai-go/pkg/credentials"
	"github.com/inhies/go-bytesize"
	log "github.com/sirupsen/logrus"
)

type Settings struct {
	AllowInsecureTLS bool   `yaml:"insecure"`
	Debug            bool   `yaml:"debug"`
	Profile          string `yaml:"profile"`
	MaxRetries       int    `yaml:"max_retries"`
}

type control struct {
	EndpointWG       *sync.WaitGroup
	StopChan         chan struct{}
	PartsChan        chan interface{}
	HaltTransmitters bool
}

var ErrUnknownPayload = errors.New("unknown payload")
var ErrFileExists = errors.New("file already exists")

type sas struct {
	Payload  string `json:"payload"`
	Profile  string `json:"profile"`
	Suffix   string `json:"suffix"`
	Filename string `json:"filename"`
}

type sasResult struct {
	SASURL   string `json:"sas_url"`
	Type     string `json:"profile_type"`
	Key      string `json:"key"`
	UploadId string `json:"upload_id"`
	BlobID   string `json:"blob_id"`
}

type Client struct {
	credentials credentials.APICredentials
	settings    Settings
}

type FileDetails struct {
	SourceFilename      string
	DestinationFilename string
	FileSuffix          string
	PayloadType         string
}

func getSAS(payload string, destinationFilename string, suffix string, credentials credentials.APICredentials, settings Settings) (sasResult, error) {
	var result sasResult

	body, err := json.Marshal(sas{payload, settings.Profile, suffix, destinationFilename})
	if err != nil {
		return result, err
	}
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
	request.Header.Add("passkey", credentials.Passkey)
	if credentials.IntegrationId != "" {
		request.Header.Add("integration_id", credentials.IntegrationId)
		request.Header.Add("integrationid", credentials.IntegrationId)
	} else {
		request.Header.Add("device_id", credentials.DeviceId)
		request.Header.Add("deviceid", credentials.DeviceId)
	}

	response, err := HTTPClient.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return result, err
	}
	switch response.StatusCode {
	case 200:
		err := json.Unmarshal(bodyBytes, &result)
		if err != nil {
			return result, err
		}
	case 415:
		return result, ErrUnknownPayload
	default:
		err := fmt.Errorf("status code: %d, Body: %v", response.StatusCode, string(bodyBytes))
		return result, err
	}
	return result, nil
}

func NewClient(settings Settings, credentials credentials.APICredentials) (Client, error) {
	client := Client{
		settings:    settings,
		credentials: credentials,
	}
	if client.settings.MaxRetries == 0 {
		client.settings.MaxRetries = 3
	}
	return client, nil
}

func (client Client) SendFile(fd FileDetails) error {
	var suffix string

	if client.settings.Profile == "" {
		client.settings.Profile = "default"
	}

	if client.settings.AllowInsecureTLS {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: client.settings.AllowInsecureTLS}
	}

	if fd.FileSuffix == "" {
		suffix = strings.Trim(filepath.Ext(fd.SourceFilename), ".")
	} else {
		suffix = fd.FileSuffix
	}
	if suffix == "" {
		return fmt.Errorf("filename %v does not have a file suffix, please set fileSuffix", fd.SourceFilename)
	}

	result, err := getSAS(fd.PayloadType, fd.DestinationFilename, suffix, client.credentials, client.settings)
	if err == ErrUnknownPayload {
		log.Warnf("Uploading file %v aborted since payload %v is not supported", fd.SourceFilename, fd.PayloadType)
		return err
	}
	if err != nil {
		return fmt.Errorf("could not generate SAS token: %v", err)
	}
	if result.Type == "azure" {
		log.Debugf("Got signed url for %v: %v", fd.SourceFilename, result.SASURL)
		err := uploadToAzureSAS(fd.SourceFilename, result, client.settings)
		if err != nil {
			return err
		}

	} else if result.Type == "s3" {
		log.Debugf("Got signed url for %v: %v", fd.SourceFilename, result.Key)
		var completeMultipartUpload completeMultipartUpload
		var control = control{
			EndpointWG:       &sync.WaitGroup{},
			StopChan:         make(chan struct{}),
			PartsChan:        make(chan interface{}),
			HaltTransmitters: false,
		}
		file, err := os.Open(fd.SourceFilename)
		if err != nil {
			return err
		}
		defer file.Close()
		stat, err := file.Stat()
		if err != nil {
			return err
		}
		fileSize := stat.Size()
		log.Infof("Uploading file %v, total %v", fd.SourceFilename, bytesize.ByteSize(fileSize).String())

		buffer := make([]byte, fileSize)
		_, err = file.Read(buffer)
		if err != nil {
			return err
		}

		var start, currentSize int
		var remaining = int(fileSize)
		var partNum = 1
		completeMultipartUpload.EventType = fd.PayloadType
		completeMultipartUpload.Key = result.Key
		completeMultipartUpload.UploadId = result.UploadId

		// Create channel for chunks to handle
		ChunkChan := make(chan transmitterPayload, partsTransmitterWorkers)
		// Start workers
		for i := 0; i < partsTransmitterWorkers; i++ {
			//log.Infoln("Starting transmitter worker " + strconv.Itoa(i))
			go partsTransmitter(ChunkChan, control)
		}
		// Collect data from completed multiparts
		go func() {
			for {
				select {
				case partsOrErr := <-control.PartsChan:
					if partsOrErr == nil {
						control.EndpointWG.Done()
					} else {
						log.Debugf("  ... transfer part %v completed", partsOrErr.(parts).PartNumber)
						completeMultipartUpload.Parts = append(completeMultipartUpload.Parts, partsOrErr.(parts))
						control.EndpointWG.Done()
					}
				case <-control.StopChan:
					// Job is done, exit function
					return
				}
			}
		}()

		for start = 0; remaining > 0; start += partSize {
			for {
				if control.HaltTransmitters {
					break
				}
				if len(ChunkChan) < partsTransmitterWorkers {
					if remaining < partSize {
						currentSize = remaining
					} else {
						currentSize = partSize
					}
					signedURL, err := getSignedURL(result, partNum, client.credentials)
					if err != nil {
						return err
					}
					control.EndpointWG.Add(1)
					remaining -= currentSize
					ChunkChan <- transmitterPayload{signedURL.SignedURL, bytes.NewReader(buffer[start : start+currentSize]), partNum, remaining}
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
			result, err := abortMultipartUpload(result, client.credentials)
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
			result, err := completeUpload(result, completeMultipartUpload.Parts, client.credentials)
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
