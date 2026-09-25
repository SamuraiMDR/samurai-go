package transmitter

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeBlob serves the payload API and an Azure blob endpoint.
type fakeBlob struct {
	srv *httptest.Server

	mu          sync.Mutex
	exists      bool // HEAD finds the blob
	putStatus   int  // status for PUT, 0 means 201
	putErrCode  string
	puts        int
	ifNoneMatch string
	body        []byte
}

func newFakeBlob(t *testing.T) *fakeBlob {
	t.Helper()
	f := &fakeBlob{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeBlob) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/cts/payload":
		_ = json.NewEncoder(w).Encode(map[string]string{
			"profile_type": "azure",
			"sas_url":      f.srv.URL + "/account/container/blob.json?sv=2024&sig=secret",
			"blob_id":      "blob",
		})
	case r.Method == http.MethodHead:
		if f.exists {
			w.Header().Set("ETag", `"0x1"`)
			return
		}
		w.Header().Set("x-ms-error-code", "BlobNotFound")
		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodPut:
		f.puts++
		f.ifNoneMatch = r.Header.Get("If-None-Match")
		f.body, _ = io.ReadAll(r.Body)
		if f.putStatus != 0 {
			w.Header().Set("x-ms-error-code", f.putErrCode)
			w.WriteHeader(f.putStatus)
			return
		}
		w.Header().Set("ETag", `"0x2"`)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "unexpected request", http.StatusBadRequest)
	}
}

func TestAzureUpload(t *testing.T) {
	f := newFakeBlob(t)
	client := newTestClient(t, f.srv.URL, true)
	file := writeTempFile(t, "payload.json", []byte(`{"alert":1}`))

	if err := client.SendFile(t.Context(), FileDetails{SourceFilename: file, PayloadType: "bouncer"}); err != nil {
		t.Fatal(err)
	}
	if f.puts != 1 || string(f.body) != `{"alert":1}` {
		t.Fatalf("puts = %d, body = %q", f.puts, f.body)
	}
	if f.ifNoneMatch != "*" {
		t.Fatalf("If-None-Match = %q, want * so an existing blob is never overwritten", f.ifNoneMatch)
	}
}

func TestAzureUploadUsesClientTransport(t *testing.T) {
	f := newFakeBlob(t)
	client := newTestClient(t, f.srv.URL, false)
	file := writeTempFile(t, "payload.json", []byte("{}"))

	// Verification stays on, trusting only the test server's CA. The Azure
	// SDK's default transport does not trust it, so the upload can only
	// succeed if it goes through the client's own transport.
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	client.transport.TLSClientConfig.RootCAs = pool

	if err := client.SendFile(t.Context(), FileDetails{SourceFilename: file, PayloadType: "bouncer"}); err != nil {
		t.Fatal(err)
	}
	if f.puts != 1 {
		t.Fatalf("puts = %d, want 1", f.puts)
	}
}

func TestAzureUploadExistingBlob(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeBlob)
		puts  int
	}{
		{"found by the existence check", func(f *fakeBlob) { f.exists = true }, 0},
		{"created after the existence check", func(f *fakeBlob) {
			f.putStatus, f.putErrCode = http.StatusConflict, "BlobAlreadyExists"
		}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeBlob(t)
			c.setup(f)
			client := newTestClient(t, f.srv.URL, true)
			file := writeTempFile(t, "payload.json", []byte("{}"))

			err := client.SendFile(t.Context(), FileDetails{SourceFilename: file, PayloadType: "bouncer"})
			if !errors.Is(err, ErrFileExists) {
				t.Fatalf("SendFile error = %v, want ErrFileExists", err)
			}
			if f.puts != c.puts {
				t.Fatalf("puts = %d, want %d", f.puts, c.puts)
			}
		})
	}
}

func TestAzureUploadGivesUpAfterMaxRetries(t *testing.T) {
	f := newFakeBlob(t)
	f.putStatus, f.putErrCode = http.StatusInternalServerError, "InternalError"
	client := newTestClient(t, f.srv.URL, true)
	file := writeTempFile(t, "payload.json", []byte("{}"))

	err := client.SendFile(t.Context(), FileDetails{SourceFilename: file, PayloadType: "bouncer"})
	if err == nil || !strings.Contains(err.Error(), "after 3 tries") || !strings.Contains(err.Error(), "InternalError") {
		t.Fatalf("SendFile error = %v, want it to report 3 tries and the last error", err)
	}
	if strings.Contains(err.Error(), "sig=secret") {
		t.Fatalf("error leaks the SAS signature: %v", err)
	}
	if f.puts != 3 {
		t.Fatalf("puts = %d, want 3", f.puts)
	}
}
