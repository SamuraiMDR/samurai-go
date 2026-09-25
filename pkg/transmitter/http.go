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
package transmitter

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/SamuraiMDR/samurai-go/pkg/credentials"
)

// errRedirect is returned instead of following a redirect. Go forwards custom
// headers such as x-api-key and passkey to the redirect target, including to
// other hosts and from https to http, so following one could leak credentials.
var errRedirect = errors.New("redirect not followed")

// newTransport returns a transport owned by a single Client. TLS settings are
// applied here rather than to http.DefaultTransport so that one client's
// AllowInsecureTLS never weakens other clients or other code in the process.
func newTransport(settings Settings) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: settings.AllowInsecureTLS, // #nosec G402 -- explicit opt-in via Settings.AllowInsecureTLS
	}
	return transport
}

// httpClient returns an http.Client that uses the client's own transport and
// refuses to follow redirects.
func (client Client) httpClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: client.transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}
}

// setAPIHeaders sets the headers for a payload API request. ExtraHeaders are
// applied first so they can never replace or duplicate the auth headers.
func setAPIHeaders(request *http.Request, credentials credentials.APICredentials) {
	for key, value := range credentials.ExtraHeaders {
		request.Header.Set(key, value)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-api-key", credentials.APIKey)
	request.Header.Set("passkey", credentials.Passkey)
	if credentials.IntegrationId != "" {
		request.Header.Set("integration_id", credentials.IntegrationId)
		request.Header.Set("integrationid", credentials.IntegrationId)
	} else {
		request.Header.Set("device_id", credentials.DeviceId)
		request.Header.Set("deviceid", credentials.DeviceId)
	}
}

const (
	// maxResponseSize caps how much of a payload API response is read. Real
	// responses are a few hundred bytes of JSON.
	maxResponseSize = 1 << 20
	// maxErrorBodySize caps how much of an error response ends up in the
	// returned error, and so in the caller's logs.
	maxErrorBodySize = 512
)

// readResponseBody reads at most maxResponseSize bytes. truncated reports
// whether the body was longer than that.
func readResponseBody(body io.Reader) (data []byte, truncated bool, err error) {
	data, err = io.ReadAll(io.LimitReader(body, maxResponseSize+1))
	if len(data) > maxResponseSize {
		return data[:maxResponseSize], true, err
	}
	return data, false, err
}

// errorBody formats an error response body for an error message. It is
// quoted so that control characters and newlines cannot forge log lines, and
// truncated to maxErrorBodySize bytes.
func errorBody(data []byte) string {
	if len(data) > maxErrorBodySize {
		return fmt.Sprintf("%q (truncated)", data[:maxErrorBodySize])
	}
	return fmt.Sprintf("%q", data)
}

// errResponseTooLarge is returned when a successful response is larger than
// maxResponseSize.
var errResponseTooLarge = fmt.Errorf("response body exceeds %d bytes", maxResponseSize)

// validateUploadURL checks a signed upload URL returned by the payload API
// before any file content is sent to it. The file must only ever travel over
// https. Errors do not include the URL, since its query string is a credential.
func validateUploadURL(rawURL string) error {
	if rawURL == "" {
		return errors.New("upload url is empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("upload url could not be parsed")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("upload url must use https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("upload url has no host")
	}
	if u.User != nil {
		return errors.New("upload url must not contain user info")
	}
	return nil
}
