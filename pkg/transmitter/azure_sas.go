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
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/inhies/go-bytesize"
	log "github.com/sirupsen/logrus"
)

// uploadToAzureSAS uploads filename to the blob behind sr.SASURL. It returns
// ErrFileExists if the blob is already there, including when another writer
// creates it between the existence check and the upload.
func (client Client) uploadToAzureSAS(ctx context.Context, filename string, sr sasResult) error {
	settings := client.settings
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
	// Do not let the client retry, we need to do it ourselves. The client's
	// own transport is used so that its TLS settings apply here too.
	blobClient, err := blockblob.NewClientWithNoCredential(sr.SASURL, &blockblob.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Retry: policy.RetryOptions{
				MaxRetries: -1,
			},
			Transport: client.httpClient(time.Second * 600),
		},
	})
	if err != nil {
		return redactError(err, sr.SASURL)
	}

	for retry := 0; retry < settings.MaxRetries; retry++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("upload of %v stopped: %w", filename, err)
		}
		log.Debugf("Try %v of %v", retry+1, settings.MaxRetries)
		// Check if the blob exists by getting its properties
		_, err = blobClient.GetProperties(ctx, nil)
		err = redactError(err, sr.SASURL)
		if err == nil {
			// The client should not retry if the blob already exists
			return ErrFileExists
		}
		log.Debugf("Properties error: %v", err)
		if !bloberror.HasCode(err, bloberror.BlobNotFound) {
			log.Errorf("failed to get blob properties: %v, blob_id %v. Try %v of %v", err, sr.BlobID, retry+1, settings.MaxRetries)
			continue
		}

		// Upload the file since it was not found. If-None-Match: * makes the
		// write fail instead of overwriting a blob created since the check.
		_, err = blobClient.UploadFile(ctx, fileHandler,
			&azblob.UploadFileOptions{
				BlockSize:   int64(104857600),
				Concurrency: uint16(3),
				AccessConditions: &blob.AccessConditions{
					ModifiedAccessConditions: &blob.ModifiedAccessConditions{
						IfNoneMatch: to.Ptr(azcore.ETagAny),
					},
				},
			})
		err = redactError(err, sr.SASURL)
		if bloberror.HasCode(err, bloberror.BlobAlreadyExists, bloberror.ConditionNotMet) {
			return ErrFileExists
		}
		if err != nil {
			log.Errorf("failed to upload file: %v, blob_id %v. Try %v of %v", err, sr.BlobID, retry+1, settings.MaxRetries)
			continue
		}
		if settings.Debug {
			log.Debugf("Uploaded file %v, blob_id %v to %v, total %v. Try %v of %v", filename, sr.BlobID, redactURL(sr.SASURL), bytesize.ByteSize(fileSize).String(), retry+1, settings.MaxRetries)
		} else {
			log.Infof("Uploaded file %v, blob_id %v, total %v. Try %v of %v", filename, sr.BlobID, bytesize.ByteSize(fileSize).String(), retry+1, settings.MaxRetries)
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("upload of %v stopped: %w", filename, err)
	}
	return fmt.Errorf("failed to send payload after %v tries: %w", settings.MaxRetries, err)
}
