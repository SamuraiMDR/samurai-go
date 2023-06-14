package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/NTTS-Innovation/samurai-go/pkg/transmitter"
	"gopkg.in/yaml.v2"
)

func NewTransmitterSettings(configFile string) (transmitter.Settings, error) {
	settings := transmitter.Settings{
		Debug:   false,
		Profile: "default",
		URL:     "",
	}

	if configFile != "" {
		data, err := os.ReadFile(filepath.Clean(configFile))
		if err != nil {
			return transmitter.Settings{}, err
		}

		err = yaml.Unmarshal(data, &settings)
		if err != nil {
			return transmitter.Settings{}, err
		}
	} else {
		return transmitter.Settings{}, fmt.Errorf("settings file path is required")
	}

	err := ValidateSettings(settings)
	if err != nil {
		return transmitter.Settings{}, err
	}
	return settings, nil
}

func ValidateSettings(settings transmitter.Settings) error {
	checks := []struct {
		bad    bool
		errMsg string
	}{
		{settings.Profile == "", "no profile defined, example 'default'"},
		{settings.URL == "", "URL not defined"},
	}

	for _, check := range checks {
		if check.bad {
			return fmt.Errorf("invalid settings: %s", check.errMsg)
		}
	}
	return nil
}

func NewTransmitterCredentials(configFile string) (transmitter.Credentials, error) {
	credentials := transmitter.Credentials{
		APIKey:   "",
		Passkey:  "",
		DeviceId: "",
	}

	if configFile != "" {
		data, err := os.ReadFile(filepath.Clean(configFile))
		if err != nil {
			return transmitter.Credentials{}, err
		}

		err = yaml.Unmarshal(data, &credentials)
		if err != nil {
			return transmitter.Credentials{}, err
		}
	} else {
		return transmitter.Credentials{}, fmt.Errorf("settings file path is required")
	}

	err := ValidateCredentials(credentials)
	if err != nil {
		return transmitter.Credentials{}, err
	}
	return credentials, nil
}

func ValidateCredentials(credentials transmitter.Credentials) error {
	checks := []struct {
		bad    bool
		errMsg string
	}{
		{credentials.APIKey == "", "apiKey is undefined"},
		{credentials.DeviceId == "", "deviceId is undefined"},
		{credentials.Passkey == "", "passkey is undefined"},
	}

	for _, check := range checks {
		if check.bad {
			return fmt.Errorf("invalid credentials: %s", check.errMsg)
		}
	}
	return nil
}
