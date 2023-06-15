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

func NewTransmitterSettings(configFile string) (transmitter.Settings, error) {
	settings := transmitter.Settings{
		Debug:    false,
		Profile:  "default",
		URL:      "",
		APIKey:   "",
		Passkey:  "",
		DeviceId: "",
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

	err := Validate(settings)
	if err != nil {
		return transmitter.Settings{}, err
	}
	return settings, nil
}

func Validate(settings transmitter.Settings) error {
	checks := []struct {
		bad    bool
		errMsg string
	}{
		{settings.Profile == "", "no profile defined, example 'default'"},
		{settings.URL == "", "URL not defined"},
		{settings.APIKey == "", "apiKey is undefined"},
		{settings.DeviceId == "", "deviceId is undefined"},
		{settings.Passkey == "", "passkey is undefined"},
	}

	for _, check := range checks {
		if check.bad {
			return fmt.Errorf("invalid settings: %s", check.errMsg)
		}
	}
	return nil
}
