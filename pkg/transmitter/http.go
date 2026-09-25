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
	"net/http"
	"time"
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
