package transmitter

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
