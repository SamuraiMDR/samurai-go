[![Go Report Card](https://goreportcard.com/badge/github.com/NTTS-Innovation/samurai-go)](https://goreportcard.com/report/github.com/NTTS-Innovation/samurai-go)
[![GitHub tag](https://img.shields.io/github/tag/NTTS-Innovation/samurai-go.svg)](https://github.com/NTTS-Innovation/samurai-go/tags)
------
# Samurai Go client SDK

The Samurai Go SDK provides simple APIs to interact with NTT Security Holdings Samurai MDR service

Examples of how to use the SDK is provided in the examples folder

## Transmitter

Transmitter client uploads a selected set of file types (payloads) to Samurai MDR service using onetime pre-signed URLs to Microsoft Azure blob storage or S3/MinIO buckets.

### Installation
```
go get github.com/NTTS-Innovation/samurai-go@v1.0.4
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

### Usage with generator package

```
import {
"github.com/NTTS-Innovation/samurai-go/pkg/generator"
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

	ws_alert := ... // your struct with a MapToAlertCIM func

	cim_alert, err := ws_alert.MapToAlertCIM(integration_name)
	if err != nil {
		log.Errorf("Failed to convert trigger due to: %v", err)
		continue
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


func (ws *WithSecureAlert) MapToAlertCIM(integration_name string) (generator.Alert, error) {
	cim_alert := generator.GetBaseAlert()
	
	known_block_actions := []string{"blocked", "disinfected", "quarantined", "deleted", "trashed"}
	if contains(known_block_actions, ws.Action) {
		cim_alert.Action = "BLOCK"
	} else {
		// defaulting to allow if unknown action
		cim_alert.Action = "ACCEPT"
	}

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
	cim_alert.Context["severity"] = ws.Severity

	/* Set time fields */
	t, err := time.Parse("2006-01-02T15:04:05.999Z", ws.PersistenceTimestamp)
	if err != nil {
		return cim_alert, fmt.Errorf("Unable to parse PersistenceTimestamp value %s, struct: %+v", ws.PersistenceTimestamp, ws)
	}
	cim_alert.AddTimeStampFields(t)
	cim_alert.SetSha()

	err = cim_alert.ValidateAlert()

	if err != nil {
		return cim_alert, fmt.Errorf("Validate failed due to '%v', alert cim: ========%+v======= based on struct: =======%+v=======", err, cim_alert, ws)
	}

	return cim_alert, err
}

```