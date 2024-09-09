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
package main

import (
	"os"

	"github.com/SamuraiMDR/samurai-go/examples/transmitter/config"
	"github.com/SamuraiMDR/samurai-go/pkg/transmitter"
	log "github.com/sirupsen/logrus"
)

func main() {
	var filename string
	var payloadType string
	var destinationFilename string

	configFile := "config.yaml"
	settings, err := config.NewTransmitterSettings(configFile)
	if err != nil {
		log.Fatal(err)
	}
	credFile := "credentials.yaml"
	creds, err := config.NewTransmitterCredentials(credFile)
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) == 3 {
		filename = os.Args[1]
		payloadType = os.Args[2]
		if err != nil {
			panic(err)
		}
	} else if len(os.Args) == 4 {
		filename = os.Args[1]
		payloadType = os.Args[2]
		destinationFilename = os.Args[3]
		if err != nil {
			panic(err)
		}
	} else {
		log.Fatalln("filename or payload argument is missing")
	}

	client, err := transmitter.NewClient(settings, creds)
	if err != nil {
		log.Fatal(err)
	}

	err = client.SendFile(filename, "", payloadType, destinationFilename)
	if err != nil {
		log.Fatal(err)
	}
}
