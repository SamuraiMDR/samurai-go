package main

import (
	"os"

	"github.com/NTTS-Innovation/samurai-go/examples/transmitter/config"
	"github.com/NTTS-Innovation/samurai-go/pkg/transmitter"
	log "github.com/sirupsen/logrus"
)

func main() {
	var filename string
	var payloadType string

	configFile := "config.yaml"
	credFile := "cred.yaml"
	settings, err := config.NewTransmitterSettings(configFile)
	if err != nil {
		log.Fatal(err)
	}
	credentials, err := config.NewTransmitterCredentials(credFile)
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) == 3 {
		filename = os.Args[1]
		payloadType = os.Args[2]
		if err != nil {
			panic(err)
		}
	} else {
		log.Fatalln("filename or payload argument is missing")
	}
	err = transmitter.SendFile(filename, payloadType, settings, credentials)
	if err != nil {
		log.Fatal(err)
	}
}
