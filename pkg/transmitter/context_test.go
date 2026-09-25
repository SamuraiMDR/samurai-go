package transmitter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// hang blocks until the client goes away, or gives up after a few seconds so
// a broken test cannot wedge the server. The body is drained first because
// the HTTP/1 server only notices a client disconnect once it has read it.
func hang(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	select {
	case <-r.Context().Done():
	case <-time.After(5 * time.Second):
	}
}

func TestSendFileCancelledContext(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(srv.Close)
	client := newTestClient(t, srv.URL, true)
	file := writeTempFile(t, "payload.json", []byte("{}"))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := client.SendFile(ctx, FileDetails{SourceFilename: file, PayloadType: "bouncer"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SendFile error = %v, want context.Canceled", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("server received %d requests after cancellation", requests.Load())
	}
}

func TestSendFileDeadline(t *testing.T) {
	cases := []struct {
		name string
		// server returns the payload API URL. It may start other servers.
		server func(t *testing.T) string
	}{
		{
			name: "payload api hangs",
			server: func(t *testing.T) string {
				srv := httptest.NewTLSServer(http.HandlerFunc(hang))
				t.Cleanup(srv.Close)
				return srv.URL
			},
		},
		{
			name: "azure upload hangs",
			server: func(t *testing.T) string {
				blob := httptest.NewServer(http.HandlerFunc(hang))
				t.Cleanup(blob.Close)
				api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_ = json.NewEncoder(w).Encode(map[string]string{
						"profile_type": "azure",
						"sas_url":      blob.URL + "/container/blob.json?sig=x",
					})
				}))
				t.Cleanup(api.Close)
				return api.URL
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := newTestClient(t, c.server(t), true)
			file := writeTempFile(t, "payload.json", []byte("{}"))

			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			err := client.SendFile(ctx, FileDetails{SourceFilename: file, PayloadType: "bouncer"})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("SendFile error = %v, want context.DeadlineExceeded", err)
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("SendFile returned after %v, want it to stop at the deadline", elapsed)
			}
		})
	}
}
