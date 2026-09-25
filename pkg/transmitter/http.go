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
	"net/http"
	"time"
)

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

// httpClient returns an http.Client that uses the client's own transport.
func (client Client) httpClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: client.transport,
		Timeout:   timeout,
	}
}
