[![Go Report Card](https://goreportcard.com/badge/github.com/NTTS-Innovation/samurai-go)](https://goreportcard.com/report/github.com/NTTS-Innovation/samurai-go)
[![GitHub tag](https://img.shields.io/github/tag/NTTS-Innovation/samurai-go.svg)](https://github.com/NTTS-Innovation/samurai-go/releases/latest)
------
# Samurai Go client SDK

The Samurai Go SDK provies simple APIs to interact with NTT Security Holdings Samurai MDR service

Examples of how to use the SDK is provided in the examples folder

## Transmitter

Transmitter client uploads a selected set of file types (payloads) to Samurai MDR service using onetime pre-signed URLs to Microsoft Azure blob storage or S3/MinIO buckets.

### Installation
```
go get github.com/NTTS-Innovation/samurai-go@v1.0.0
```

### Usage
```
package main

import (
	"log"

	"github.com/NTTS-Innovation/samurai-go/pkg/credentials"
	"github.com/NTTS-Innovation/samurai-go/pkg/transmitter"
)

func main() {
	filename := "/example/filename"
	payloadType := "pcap"

	credentials := credentials.APICredentials{
		URL:      "https://...",
		APIKey:   "apikey",
		Passkey:  "passkey",
		DeviceId: "deviceid",
	}

	settings := transmitter.Settings{
		Debug:   false,
		Profile: "default",
	}

	client, err := transmitter.NewClient(settings, credentials)
	if err != nil {
		log.Fatal(err)
	}

	err := client.SendFile(filename, payloadType)
	if err != nil {
		log.Fatal(err)
	}
}

```
