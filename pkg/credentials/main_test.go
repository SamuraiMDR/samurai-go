package credentials

import (
	"errors"
	"strings"
	"testing"
)

func valid() APICredentials {
	return APICredentials{
		URL:      "https://api.example.com/v1",
		APIKey:   "key",
		Passkey:  "pass",
		DeviceId: "device",
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		modify  func(*APICredentials)
		wantErr string
	}{
		{"valid device id", func(c *APICredentials) {}, ""},
		{"valid integration id", func(c *APICredentials) { c.DeviceId = ""; c.IntegrationId = "integration" }, ""},
		{"device and integration id", func(c *APICredentials) { c.IntegrationId = "integration" }, ""},
		{"custom extra header", func(c *APICredentials) { c.ExtraHeaders = map[string]string{"X-Tenant": "t"} }, ""},
		{"missing url", func(c *APICredentials) { c.URL = "" }, "url is not set"},
		{"http url", func(c *APICredentials) { c.URL = "http://api.example.com" }, "url must use https"},
		{"no scheme", func(c *APICredentials) { c.URL = "api.example.com" }, "url must use https"},
		{"no host", func(c *APICredentials) { c.URL = "https:///v1" }, "url has no host"},
		{"user info", func(c *APICredentials) { c.URL = "https://user:secret@api.example.com" }, "user info"},
		{"query", func(c *APICredentials) { c.URL = "https://api.example.com/?a=b" }, "query or fragment"},
		{"fragment", func(c *APICredentials) { c.URL = "https://api.example.com/#a" }, "query or fragment"},
		{"unparsable url", func(c *APICredentials) { c.URL = "https://api.example.com/%zz" }, "could not be parsed"},
		{"missing api key", func(c *APICredentials) { c.APIKey = "" }, "apiKey is not set"},
		{"missing passkey", func(c *APICredentials) { c.Passkey = "" }, "passkey is not set"},
		{"missing ids", func(c *APICredentials) { c.DeviceId = "" }, "deviceId or integrationId"},
		{"reserved header", func(c *APICredentials) { c.ExtraHeaders = map[string]string{"X-API-Key": "x"} }, "must not set"},
		{"reserved id header", func(c *APICredentials) { c.ExtraHeaders = map[string]string{"deviceid": "x"} }, "must not set"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cred := valid()
			c.modify(&cred)
			err := cred.Validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidCredentials) || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error = %v, want ErrInvalidCredentials containing %q", err, c.wantErr)
			}
		})
	}
}

func TestValidateDoesNotLeakSecrets(t *testing.T) {
	cred := valid()
	cred.URL = "https://user:secret@api.example.com/%zz"
	err := cred.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaks the url: %v", err)
	}
}
