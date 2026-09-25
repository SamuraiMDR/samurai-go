package transmitter

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/SamuraiMDR/samurai-go/pkg/credentials"
)

// newTestServer returns a TLS server with a self-signed certificate that
// answers every payload request with an unsupported profile type, so SendFile
// stops right after the SAS request.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"profile_type":"unsupported"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestClient(t *testing.T, url string, insecure bool) Client {
	t.Helper()
	client, err := NewClient(Settings{AllowInsecureTLS: insecure}, credentials.APICredentials{
		URL:      url,
		APIKey:   "key",
		Passkey:  "pass",
		DeviceId: "device",
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInsecureTLSIsScopedToClient(t *testing.T) {
	srv := newTestServer(t)
	file := writeTempFile(t, "payload.json", []byte("{}"))

	insecure := newTestClient(t, srv.URL, true)
	err := insecure.SendFile(FileDetails{SourceFilename: file, PayloadType: "bouncer"})
	if err == nil || !strings.Contains(err.Error(), "unknown result type") {
		t.Fatalf("insecure client should reach the self-signed server, got %v", err)
	}

	if cfg := http.DefaultTransport.(*http.Transport).TLSClientConfig; cfg != nil && cfg.InsecureSkipVerify {
		t.Fatal("AllowInsecureTLS leaked into http.DefaultTransport")
	}

	secure := newTestClient(t, srv.URL, false)
	err = secure.SendFile(FileDetails{SourceFilename: file, PayloadType: "bouncer"})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("secure client must reject the self-signed server, got %v", err)
	}
}

func TestNewTransportDefaultsToVerifiedTLS12(t *testing.T) {
	transport := newTransport(Settings{})
	if transport == http.DefaultTransport {
		t.Fatal("transport must not be http.DefaultTransport")
	}
	cfg := transport.TLSClientConfig
	if cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must be off unless AllowInsecureTLS is set")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want at least TLS 1.2", cfg.MinVersion)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var targetHit atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit.Store(true)
	}))
	t.Cleanup(target.Close)
	origin := httptest.NewTLSServer(http.RedirectHandler(target.URL+"/cts/payload", http.StatusTemporaryRedirect))
	t.Cleanup(origin.Close)

	client := newTestClient(t, origin.URL, true)
	if _, err := client.getSAS("bouncer", "", "json", "", ""); !errors.Is(err, errRedirect) {
		t.Fatalf("getSAS error = %v, want errRedirect", err)
	}
	if _, err := client.sendRequest([]byte("{}")); !errors.Is(err, errRedirect) {
		t.Fatalf("sendRequest error = %v, want errRedirect", err)
	}
	if targetHit.Load() {
		t.Fatal("redirect target received a request carrying the API credentials")
	}
}

func TestAPIHeaders(t *testing.T) {
	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Settings{AllowInsecureTLS: true}, credentials.APICredentials{
		URL:           srv.URL,
		APIKey:        "key",
		Passkey:       "pass",
		IntegrationId: "integration",
		ExtraHeaders:  map[string]string{"X-Tenant": "tenant"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// NewClient rejects reserved ExtraHeaders. Inject them afterwards to check
	// that setAPIHeaders still lets the auth headers win.
	client.credentials.ExtraHeaders = map[string]string{
		"x-api-key": "override",
		"Passkey":   "override",
		"X-Tenant":  "tenant",
	}
	// getSAS covers the SAS request, sendRequest covers the S3 multipart calls.
	if _, err := client.getSAS("bouncer", "", "json", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.sendRequest([]byte("{}")); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"X-Api-Key":      "key",
		"Passkey":        "pass",
		"Integration_id": "integration",
		"Integrationid":  "integration",
		"X-Tenant":       "tenant",
	}
	if len(seen) != 2 {
		t.Fatalf("got %d requests, want 2", len(seen))
	}
	for i, h := range seen {
		for name, value := range want {
			if got := h.Values(name); len(got) != 1 || got[0] != value {
				t.Errorf("request %d: %s = %q, want [%q]", i, name, got, value)
			}
		}
		for _, name := range []string{"Device_id", "Deviceid"} {
			if got := h.Values(name); len(got) != 0 {
				t.Errorf("request %d: unexpected %s = %q for an integration id client", i, name, got)
			}
		}
	}
}

func TestNewClientRejectsInvalidCredentials(t *testing.T) {
	_, err := NewClient(Settings{}, credentials.APICredentials{
		URL:      "http://api.example.com",
		APIKey:   "key",
		Passkey:  "pass",
		DeviceId: "device",
	})
	if !errors.Is(err, credentials.ErrInvalidCredentials) {
		t.Fatalf("NewClient error = %v, want ErrInvalidCredentials", err)
	}
}

func TestReadResponseBody(t *testing.T) {
	data, truncated, err := readResponseBody(strings.NewReader(strings.Repeat("a", maxResponseSize)))
	if err != nil || truncated || len(data) != maxResponseSize {
		t.Fatalf("body of exactly the limit: len=%d truncated=%v err=%v", len(data), truncated, err)
	}
	data, truncated, err = readResponseBody(strings.NewReader(strings.Repeat("a", maxResponseSize+10)))
	if err != nil || !truncated || len(data) != maxResponseSize {
		t.Fatalf("body over the limit: len=%d truncated=%v err=%v", len(data), truncated, err)
	}
}

func TestErrorBody(t *testing.T) {
	if got := errorBody([]byte("bad\nrequest")); got != `"bad\nrequest"` {
		t.Fatalf("errorBody did not quote the newline: %s", got)
	}
	got := errorBody([]byte(strings.Repeat("x", maxErrorBodySize+100)))
	if !strings.HasSuffix(got, "(truncated)") || len(got) > maxErrorBodySize+20 {
		t.Fatalf("errorBody did not truncate: len=%d", len(got))
	}
}

func TestAPIResponseLimits(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		check  func(t *testing.T, err error)
	}{
		{
			name:   "error body is quoted and truncated",
			status: http.StatusInternalServerError,
			body:   "line one\nlevel=error msg=forged\n" + strings.Repeat("x", 4096),
			check: func(t *testing.T, err error) {
				if err == nil || !strings.Contains(err.Error(), "status code: 500") {
					t.Fatalf("error = %v, want status code 500", err)
				}
				if strings.Contains(err.Error(), "\n") {
					t.Fatalf("error contains a raw newline: %q", err)
				}
				if len(err.Error()) > maxErrorBodySize+100 {
					t.Fatalf("error is %d bytes, want it truncated", len(err.Error()))
				}
			},
		},
		{
			name:   "oversized success response is rejected",
			status: http.StatusOK,
			body:   `{"signed_url":"` + strings.Repeat("x", maxResponseSize) + `"}`,
			check: func(t *testing.T, err error) {
				if !errors.Is(err, errResponseTooLarge) {
					t.Fatalf("error = %v, want errResponseTooLarge", err)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			t.Cleanup(srv.Close)
			client := newTestClient(t, srv.URL, true)

			_, err := client.getSAS("bouncer", "", "json", "", "")
			c.check(t, err)
			_, err = client.sendRequest([]byte("{}"))
			c.check(t, err)
		})
	}
}
