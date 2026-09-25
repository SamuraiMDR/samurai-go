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
package credentials

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type APICredentials struct {
	URL           string            `yaml:"url"`
	APIKey        string            `yaml:"apiKey"`
	Passkey       string            `yaml:"passkey"`
	DeviceId      string            `yaml:"deviceId"`
	IntegrationId string            `yaml:"integrationId"`
	ExtraHeaders  map[string]string `yaml:"extraHeaders,omitempty"`
}

var ErrInvalidCredentials = errors.New("invalid credentials")

// reservedHeaders are set by the SDK itself and must not come from
// ExtraHeaders. Keys are lowercase.
var reservedHeaders = map[string]bool{
	"content-type":   true,
	"host":           true,
	"x-api-key":      true,
	"passkey":        true,
	"device_id":      true,
	"deviceid":       true,
	"integration_id": true,
	"integrationid":  true,
}

// Validate checks that the credentials are complete and safe to send. The URL
// must use https since the API key and passkey travel in request headers.
// Error messages never include the URL or any secret.
func (c APICredentials) Validate() error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidCredentials, fmt.Sprintf(format, args...))
	}

	if c.URL == "" {
		return invalid("url is not set")
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return invalid("url could not be parsed")
	}
	if u.Scheme != "https" {
		return invalid("url must use https")
	}
	if u.Host == "" {
		return invalid("url has no host")
	}
	if u.User != nil {
		return invalid("url must not contain user info")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return invalid("url must not contain a query or fragment")
	}
	if c.APIKey == "" {
		return invalid("apiKey is not set")
	}
	if c.Passkey == "" {
		return invalid("passkey is not set")
	}
	if c.DeviceId == "" && c.IntegrationId == "" {
		return invalid("deviceId or integrationId must be set")
	}
	for key := range c.ExtraHeaders {
		if reservedHeaders[strings.ToLower(key)] {
			return invalid("extraHeaders must not set %q", key)
		}
	}
	return nil
}
