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
go get github.com/SamuraiMDR/samurai-go@v1.0.14
```

### Usage
```
package main

import (
	"log"

	"github.com/SamuraiMDR/samurai-go/pkg/credentials"
	"github.com/SamuraiMDR/samurai-go/pkg/transmitter"
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

	err = client.SendFile(transmitter.FileDetails{
		SourceFilename:      filename,
		PayloadType:         payloadType,
	})
	if err != nil {
		log.Fatal(err)
	}
}

```

### Usage with generator package

For a concrete implementation, view the WithSecure-Integration.

```
import {
"github.com/SamuraiMDR/samurai-go/pkg/generator"
}

func main() {
	credentials := credentials.APICredentials{
		URL:      transmit_api_url,
		APIKey:   transmit_api_key,
		Passkey:  transmit_api_passkey,
		DeviceId: transmit_api_deviceid,
	}

	settings := transmitter.Settings{
		Debug:   true,
		Profile: "azure",
	}

	client, err := transmitter.NewClient(settings, credentials)
	if err != nil {
		log.Fatal(err)
	}

	cim_alert := generator.GetBaseAlertV1()
	cim_alert.Action = "BLOCK"
	
	integration_name := "xxx"

	//Add evidence blob as evidence.json
	cim_alert.SetBlobsProperties(integration_name, integration_name)
	ws_as_json, err := json.Marshal(ws)
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
	t, err := time.Parse("2006-01-02T15:04:05.999Z", "2023-03-03 16:54") // just for example
	if err != nil {
		fmt.Fatalf("Unable to parse PersistenceTimestamp value %s, struct: %+v", ws.PersistenceTimestamp, ws)
	}
	cim_alert.AddTimeStampFields(t)
	cim_alert.SetSha()

	err = cim_alert.ValidateAlert()

	if err != nil {
		fmt.Fatalf("Validate failed due to '%v', alert cim: ========%+v======= b", err, cim_alert)
	}

	log.Debugf("Succeded in converting trigger %s to alert CIM, uploading alert", cim_alert.Name)

	outp, err := json.Marshal(cim_alert)
	if err != nil {
		log.Errorf("Failed to convert to json due to %v, struct: %+v", err, cim_alert)
		continue
	}

	fn := "/tmp/alert.json"
	err = os.WriteFile(fn, outp, 0600)
	if err != nil {
		log.Errorf("Failed to write %s due to '%v'", fn, err)
		continue
	}

	err = client.SendFile(fn, "bouncer")
	if err != nil {
		log.Fatal(err)
	}
}

```
