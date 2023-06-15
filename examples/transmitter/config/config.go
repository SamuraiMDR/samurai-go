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

	"github.com/NTTS-Innovation/samurai-go/pkg/transmitter"
	"gopkg.in/yaml.v2"
)

type transmitterSettings transmitter.Settings
type transmitterCredentials transmitter.Credentials

func NewTransmitterSettings(configFile string) (transmitterSettings, error) {
	settings := transmitterSettings{
		Debug:   false,
		Profile: "default",
		URL:     "",
	}

	if configFile != "" {
		data, err := os.ReadFile(filepath.Clean(configFile))
		if err != nil {
			return transmitterSettings{}, err
		}

		err = yaml.Unmarshal(data, &settings)
		if err != nil {
			return transmitterSettings{}, err
		}
	} else {
		return settings, fmt.Errorf("settings file path is required")
	}

	err := settings.Validate()
	if err != nil {
		return transmitterSettings{}, err
	}
	return settings, nil
}

func (settings *transmitterSettings) Validate() error {
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

func NewTransmitterCredentials(configFile string) (transmitterCredentials, error) {
	credentials := transmitterCredentials{
		APIKey:   "",
		Passkey:  "",
		DeviceId: "",
	}

	if configFile != "" {
		data, err := os.ReadFile(filepath.Clean(configFile))
		if err != nil {
			return transmitterCredentials{}, err
		}

		err = yaml.Unmarshal(data, &credentials)
		if err != nil {
			return transmitterCredentials{}, err
		}
	} else {
		return transmitterCredentials{}, fmt.Errorf("settings file path is required")
	}

	err := credentials.Validate()
	if err != nil {
		return transmitterCredentials{}, err
	}
	return credentials, nil
}

func (credentials *transmitterCredentials) Validate() error {
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
