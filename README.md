[![Go Report Card](https://goreportcard.com/badge/github.com/SamuraiMDR/samurai-go)](https://goreportcard.com/report/github.com/SamuraiMDR/samurai-go)
[![GitHub tag](https://img.shields.io/github/tag/SamuraiMDR/samurai-go.svg)](https://github.com/SamuraiMDR/samurai-go/tags)
------
# Samurai Go client SDK

The Samurai Go SDK provides simple APIs to interact with NTT Security Holdings Samurai MDR service

Examples of how to use the SDK is provided in the examples folder

## Transmitter

Transmitter client uploads a selected set of file types (payloads) to Samurai MDR service using onetime pre-signed URLs to Microsoft Azure blob storage or S3/MinIO buckets.

### Installation
```
go get github.com/SamuraiMDR/samurai-go/v2@latest
```

### Usage
```go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/SamuraiMDR/samurai-go/v2/pkg/credentials"
	"github.com/SamuraiMDR/samurai-go/v2/pkg/transmitter"
)

func main() {
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

	// Cancelling the context stops the upload. An interrupted S3 multipart
	// upload is aborted instead of leaving parts behind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err = client.SendFile(ctx, transmitter.FileDetails{
		SourceFilename: "/example/filename.pcap",
		PayloadType:    "pcap",
		// Optional: DestinationFilename sets the name used in storage.
		// Optional: CustomKey/CustomValue add a single custom key/value pair
		// to the token-request body sent to the payload API.
		// CustomKey:   "source",
		// CustomValue: "example",
	})
	if err != nil {
		log.Fatal(err)
	}
}
```

`SendFile` returns `transmitter.ErrFileExists` when the destination already
exists and `transmitter.ErrUnknownPayload` when the payload type is not
supported. Compare with `errors.Is`.

### Usage with generator package

For a concrete implementation, view the WithSecure-Integration.

```go
import (
	"github.com/SamuraiMDR/samurai-go/v2/pkg/generator"
)

func main() {
	// Create client as in the example above, with Profile "azure".

	cim_alert := generator.GetBaseAlertV1()
	cim_alert.Action = "BLOCK"

	integration_name := "xxx"

	//Add evidence blob as evidence.json
	cim_alert.SetBlobsProperties(integration_name, integration_name)
	ws_as_json, err := json.Marshal(ws)
	if err != nil {
		log.Fatal(err)
	}
	cim_alert.AddJSONData(ws_as_json, "evidence", true)

	cim_alert.Src = "n/a"
	cim_alert.Dst = "n/a"
	cim_alert.ShortDesc = "WithSecure Elements EDR"
	cim_alert.DevicePhysical = integration_name
	cim_alert.DeviceVirtual = integration_name
	cim_alert.Type = "hids"
	cim_alert.Vendor = "WithSecure"
	cim_alert.Platform = "withsecure_elements"
	cim_alert.Context["severity"] = "CRITICAL"

	/* Set time fields */
	cim_alert.AddTimeStampFields(time.Now())

	// SetSha must run after every other field is set.
	if err := cim_alert.SetSha(); err != nil {
		log.Fatal(err)
	}
	if err := cim_alert.ValidateAlert(); err != nil {
		log.Fatalf("Validate failed: %v", err)
	}

	outp, err := json.Marshal(cim_alert)
	if err != nil {
		log.Fatal(err)
	}

	fn := "/tmp/alert.json"
	if err := os.WriteFile(fn, outp, 0600); err != nil {
		log.Fatal(err)
	}

	err = client.SendFile(ctx, transmitter.FileDetails{
		SourceFilename: fn,
		PayloadType:    "bouncer",
	})
	if err != nil {
		log.Fatal(err)
	}
}
```
