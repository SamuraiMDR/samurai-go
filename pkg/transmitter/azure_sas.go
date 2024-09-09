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
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/inhies/go-bytesize"
	log "github.com/sirupsen/logrus"
)

func uploadToAzureSAS(filename string, sas string, settings Settings) error {
	fileHandler, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fileHandler.Close()
	stat, err := fileHandler.Stat()
	if err != nil {
		return err
	}
	fileSize := stat.Size()

	if settings.Debug {
		log.Debugf("Uploading file %v to %v, total %v", filename, sas, bytesize.ByteSize(fileSize).String())
	} else {
		log.Infof("Uploading file %v, total %v", filename, bytesize.ByteSize(fileSize).String())
	}
	// Do not let the client retry, we need to do it ourselves
	client, err := blockblob.NewClientWithNoCredential(sas, &blockblob.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Retry: policy.RetryOptions{
				MaxRetries: -1,
			},
		},
	})
	if err != nil {
		return err
	}

	for retry := 0; retry < settings.MaxRetries; retry++ {
		log.Debugf("Try %v of %v", retry+1, settings.MaxRetries)
		// Check if the blob exists by getting its properties
		_, err = client.GetProperties(context.TODO(), nil)
		if err != nil {
			log.Debugf("Properties error: %v", err)
			var storageErr *azcore.ResponseError
			if errors.As(err, &storageErr) && storageErr.ErrorCode == "BlobNotFound" {
				// Upload the file since it was not found
				_, err = client.UploadFile(context.TODO(), fileHandler,
					&azblob.UploadFileOptions{
						BlockSize:   int64(104857600),
						Concurrency: uint16(3),
					})
				if err != nil {
					log.Errorf("failed to upload file: %v. Try %v of %v", err, retry+1, settings.MaxRetries)
				} else {
					log.Debugln("Upload completed")
					return nil
				}
			} else {
				log.Errorf("failed to get blob properties: %v", err)
			}
		} else {
			// The client should not retry if the blob already exists
			return ErrFileExists
		}
	}
	return fmt.Errorf("failed to send payload after %v retries", maxRetry)
}
