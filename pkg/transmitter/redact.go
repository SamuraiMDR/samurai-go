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
	"errors"
	"net/url"
	"strings"
)

const redacted = "REDACTED"

// Pre-signed S3 URLs and Azure SAS URLs carry their signature in the query
// string. Anyone holding the full URL can write to the target until it
// expires, so it must never reach logs or returned errors.

// redactURL returns rawURL without user info, query string or fragment.
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[unparsable url]"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// redactedError replaces the message of an error while keeping the original
// available to errors.Is and errors.As.
type redactedError struct {
	err error
	msg string
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// redactError removes the query string of signedURL from err's message.
// Wrapping errors usually build their message when they are created, so the
// text is scrubbed as a whole. Any *url.Error in the chain is also rewritten so
// that callers unwrapping it do not see the signature either.
func redactError(err error, signedURL string) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		urlErr.URL = redactURL(urlErr.URL)
	}
	msg := err.Error()
	if u, parseErr := url.Parse(signedURL); parseErr == nil {
		if u.RawQuery != "" {
			msg = strings.ReplaceAll(msg, u.RawQuery, redacted)
		}
		if u.Fragment != "" {
			msg = strings.ReplaceAll(msg, u.EscapedFragment(), redacted)
		}
	} else if signedURL != "" {
		msg = strings.ReplaceAll(msg, signedURL, redacted)
	}
	return &redactedError{err: err, msg: msg}
}
