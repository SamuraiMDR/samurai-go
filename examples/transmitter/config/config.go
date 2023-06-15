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
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/NTTS-Innovation/samurai-go/pkg/credentials"
	"github.com/NTTS-Innovation/samurai-go/pkg/transmitter"
	"gopkg.in/yaml.v2"
)

func NewTransmitterSettings(configFile string) (transmitter.Settings, error) {
	settings := transmitter.Settings{
		Debug:   false,
		Profile: "default",
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

	err := validateSettings(settings)
	if err != nil {
		return transmitter.Settings{}, err
	}
	return settings, nil
}

func validateSettings(settings transmitter.Settings) error {
	checks := []struct {
		bad    bool
		errMsg string
	}{
		{settings.Profile == "", "no profile defined, example 'default'"},
	}

	for _, check := range checks {
		if check.bad {
			return fmt.Errorf("invalid settings: %s", check.errMsg)
		}
	}
	return nil
}

func NewTransmitterCredentials(configFile string) (credentials.APICredentials, error) {
	cred := credentials.APICredentials{
		URL:      "",
		APIKey:   "",
		Passkey:  "",
		DeviceId: "",
	}

	if configFile != "" {
		data, err := os.ReadFile(filepath.Clean(configFile))
		if err != nil {
			return credentials.APICredentials{}, err
		}

		err = yaml.Unmarshal(data, &cred)
		if err != nil {
			return credentials.APICredentials{}, err
		}
	} else {
		return credentials.APICredentials{}, fmt.Errorf("settings file path is required")
	}

	err := validateCredentials(cred)
	if err != nil {
		return credentials.APICredentials{}, err
	}
	return cred, nil
}

func validateCredentials(cred credentials.APICredentials) error {
	checks := []struct {
		bad    bool
		errMsg string
	}{
		{cred.URL == "", "URL not defined"},
		{cred.APIKey == "", "apiKey is undefined"},
		{cred.DeviceId == "", "deviceId is undefined"},
		{cred.Passkey == "", "passkey is undefined"},
	}

	for _, check := range checks {
		if check.bad {
			return fmt.Errorf("invalid credentials: %s", check.errMsg)
		}
	}
	return nil
}
