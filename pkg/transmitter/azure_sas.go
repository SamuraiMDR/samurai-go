package transmitter

import (
	"context"
	"os"

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
		log.Infof("Uploading file %v to %v, total %v", filename, sas, bytesize.ByteSize(fileSize).String())
	} else {
		log.Infof("Uploading file %v, total %v", filename, bytesize.ByteSize(fileSize).String())
	}
	client, err := blockblob.NewClientWithNoCredential(sas, nil)
	if err != nil {
		return err
	}
	_, err = client.UploadFile(context.TODO(), fileHandler,
		&azblob.UploadFileOptions{
			BlockSize:   int64(104857600),
			Concurrency: uint16(3),
		})
	if err != nil {
		return err
	}
	log.Debugln("Upload completed")
	return nil
}
