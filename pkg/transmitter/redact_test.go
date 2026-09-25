package transmitter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

const secret = "topsecret"

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"https://acct.blob.core.windows.net/c/blob.json?sv=2024&sig=" + secret: "https://acct.blob.core.windows.net/c/blob.json",
		"https://s3.example.com/b/k?X-Amz-Signature=" + secret + "#frag":       "https://s3.example.com/b/k",
		"https://user:" + secret + "@example.com/p":                            "https://example.com/p",
		"https://example.com/p":                 "https://example.com/p",
		"https://example.com/%zz?sig=" + secret: "[unparsable url]",
	}
	for in, want := range cases {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactError(t *testing.T) {
	signed := "https://s3.example.com/b/k?X-Amz-Signature=" + secret
	inner := &url.Error{Op: "Put", URL: signed, Err: context.DeadlineExceeded}
	err := redactError(fmt.Errorf("upload: %w", inner), signed)

	if strings.Contains(err.Error(), secret) {
		t.Fatalf("message leaks the signature: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("errors.Is no longer reaches the original error")
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) || strings.Contains(urlErr.URL, secret) {
		t.Fatalf("unwrapped *url.Error still carries the signature: %v", urlErr)
	}
	if redactError(nil, signed) != nil {
		t.Fatal("redactError(nil) must be nil")
	}
}

// captureLogs sends logrus output to a buffer at debug level for the rest of
// the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	out, level := log.StandardLogger().Out, log.GetLevel()
	log.SetOutput(&buf)
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		log.SetOutput(out)
		log.SetLevel(level)
	})
	return &buf
}

// newPayloadAPI fakes /cts/payload. The SAS request gets sasResponse, and the
// S3 multipart calls get a signed URL or a message.
func newPayloadAPI(t *testing.T, sasResponse map[string]string, signedURL string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch body["event_type"] {
		case "GET_SIGNED_URL":
			_ = json.NewEncoder(w).Encode(map[string]string{"signed_url": signedURL})
		case "COMPLETE_MULTIPART_UPLOAD", "ABORT_MULTIPART_UPLOAD":
			_ = json.NewEncoder(w).Encode(map[string]string{"Message": "done"})
		default:
			_ = json.NewEncoder(w).Encode(sasResponse)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// unreachable is a signed URL whose connection is refused immediately.
const unreachable = "https://127.0.0.1:1/bucket/key?X-Amz-Signature=" + secret + "&sig=" + secret

func TestS3UploadDoesNotLogSignedURL(t *testing.T) {
	logs := captureLogs(t)
	api := newPayloadAPI(t, map[string]string{"profile_type": "s3", "key": "k", "upload_id": "u"}, unreachable)
	client := newTestClient(t, api.URL, true)
	file := writeTempFile(t, "payload.json", []byte("{}"))

	err := client.SendFile(FileDetails{SourceFilename: file, PayloadType: "bouncer"})
	if err != nil && strings.Contains(err.Error(), secret) {
		t.Fatalf("returned error leaks the signature: %v", err)
	}
	if !strings.Contains(logs.String(), "127.0.0.1") {
		t.Fatalf("expected the failed part upload to be logged, got:\n%s", logs)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("logs leak the signature:\n%s", logs)
	}
}

func TestAzureUploadDoesNotLogSASURL(t *testing.T) {
	logs := captureLogs(t)
	api := newPayloadAPI(t, map[string]string{"profile_type": "azure", "sas_url": unreachable, "blob_id": "b"}, "")
	client := newTestClient(t, api.URL, true)
	file := writeTempFile(t, "payload.json", []byte("{}"))

	err := client.SendFile(FileDetails{SourceFilename: file, PayloadType: "bouncer"})
	if err == nil {
		t.Fatal("expected the upload to an unreachable host to fail")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("returned error leaks the signature: %v", err)
	}
	if !strings.Contains(logs.String(), "127.0.0.1") {
		t.Fatalf("expected the failed request to be logged, got:\n%s", logs)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("logs leak the signature:\n%s", logs)
	}
}
