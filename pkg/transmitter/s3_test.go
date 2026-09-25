package transmitter

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// smallParts shrinks the part size and retry delay for the rest of the test.
func smallParts(t *testing.T, size int64) {
	t.Helper()
	oldSize, oldDelay := partSize, partRetryDelay
	partSize, partRetryDelay = size, time.Millisecond
	t.Cleanup(func() { partSize, partRetryDelay = oldSize, oldDelay })
}

// fakeS3 serves both the payload API and the S3 part uploads.
type fakeS3 struct {
	srv *httptest.Server

	mu            sync.Mutex
	parts         map[int][]byte
	attempts      map[int]int
	failTimes     map[int]int  // part -> number of attempts to fail before succeeding
	failSignedURL map[int]bool // part -> GET_SIGNED_URL always fails
	noETag        bool
	completed     []parts
	completeCalls int
	abortCalls    int
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{
		parts:         map[int][]byte{},
		attempts:      map[int]int{},
		failTimes:     map[int]int{},
		failSignedURL: map[int]bool{},
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeS3) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/upload/") {
		partNum, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/upload/"))
		body, _ := io.ReadAll(r.Body)
		f.attempts[partNum]++
		if r.ContentLength != int64(len(body)) {
			http.Error(w, "content length mismatch", http.StatusBadRequest)
			return
		}
		if f.failTimes[partNum] > 0 {
			f.failTimes[partNum]--
			http.Error(w, "<Error>SlowDown</Error>", http.StatusServiceUnavailable)
			return
		}
		f.parts[partNum] = body
		if !f.noETag {
			w.Header().Set("ETag", fmt.Sprintf(`"etag-%d"`, partNum))
		}
		return
	}

	var body struct {
		EventType string  `json:"event_type"`
		Part      int     `json:"part"`
		Parts     []parts `json:"parts"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch body.EventType {
	case "GET_SIGNED_URL":
		if f.failSignedURL[body.Part] {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"signed_url": fmt.Sprintf("%s/upload/%d?X-Amz-Signature=sig", f.srv.URL, body.Part),
		})
	case "COMPLETE_MULTIPART_UPLOAD":
		f.completeCalls++
		f.completed = body.Parts
		_ = json.NewEncoder(w).Encode(map[string]string{"Message": "completed"})
	case "ABORT_MULTIPART_UPLOAD":
		f.abortCalls++
		_ = json.NewEncoder(w).Encode(map[string]string{"Message": "aborted"})
	default:
		_ = json.NewEncoder(w).Encode(map[string]string{"profile_type": "s3", "key": "k", "upload_id": "u"})
	}
}

// assembled joins the uploaded parts in the order they were completed.
func (f *fakeS3) assembled() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out bytes.Buffer
	for _, p := range f.completed {
		out.Write(f.parts[p.PartNumber])
	}
	return out.Bytes()
}

func randomFile(t *testing.T, size int) (string, []byte) {
	t.Helper()
	data := make([]byte, size)
	_, _ = rand.Read(data)
	return writeTempFile(t, "payload.pcap", data), data
}

func TestS3UploadAllParts(t *testing.T) {
	smallParts(t, 1024)
	f := newFakeS3(t)
	client := newTestClient(t, f.srv.URL, true)
	file, data := randomFile(t, 5*1024+100)

	if err := client.SendFile(t.Context(), FileDetails{SourceFilename: file, PayloadType: "pcap"}); err != nil {
		t.Fatal(err)
	}
	if f.completeCalls != 1 || f.abortCalls != 0 {
		t.Fatalf("complete called %d times, abort %d times", f.completeCalls, f.abortCalls)
	}
	if len(f.completed) != 6 {
		t.Fatalf("completed with %d parts, want 6", len(f.completed))
	}
	for i, p := range f.completed {
		if p.PartNumber != i+1 || p.ETag != fmt.Sprintf(`"etag-%d"`, i+1) {
			t.Fatalf("completed part %d = %+v", i, p)
		}
	}
	if !bytes.Equal(f.assembled(), data) {
		t.Fatal("uploaded object differs from the file")
	}
}

func TestS3UploadEmptyFile(t *testing.T) {
	smallParts(t, 1024)
	f := newFakeS3(t)
	client := newTestClient(t, f.srv.URL, true)
	file, _ := randomFile(t, 0)

	if err := client.SendFile(t.Context(), FileDetails{SourceFilename: file, PayloadType: "pcap"}); err != nil {
		t.Fatal(err)
	}
	if len(f.completed) != 1 || len(f.parts[1]) != 0 {
		t.Fatalf("want a single empty part, got %+v", f.completed)
	}
}

func TestS3UploadRetriesWithFullPart(t *testing.T) {
	smallParts(t, 1024)
	f := newFakeS3(t)
	f.failTimes[2] = maxRetry - 1
	client := newTestClient(t, f.srv.URL, true)
	file, data := randomFile(t, 3*1024)

	if err := client.SendFile(t.Context(), FileDetails{SourceFilename: file, PayloadType: "pcap"}); err != nil {
		t.Fatal(err)
	}
	if f.attempts[2] != maxRetry {
		t.Fatalf("part 2 was sent %d times, want %d", f.attempts[2], maxRetry)
	}
	if !bytes.Equal(f.assembled(), data) {
		t.Fatal("uploaded object differs from the file after a retry")
	}
}

func TestS3UploadFailureAborts(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeS3)
		want  string
	}{
		{"part keeps failing", func(f *fakeS3) { f.failTimes[3] = maxRetry }, "part 3 failed after"},
		{"signed url keeps failing", func(f *fakeS3) { f.failSignedURL[2] = true }, "could not get signed url"},
		{"part has no etag", func(f *fakeS3) { f.noETag = true }, "no ETag"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			smallParts(t, 1024)
			f := newFakeS3(t)
			c.setup(f)
			client := newTestClient(t, f.srv.URL, true)
			file, _ := randomFile(t, 5*1024)

			before := runtime.NumGoroutine()
			err := client.SendFile(t.Context(), FileDetails{SourceFilename: file, PayloadType: "pcap"})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("SendFile error = %v, want it to contain %q", err, c.want)
			}
			if f.completeCalls != 0 || f.abortCalls != 1 {
				t.Fatalf("complete called %d times, abort %d times; want 0 and 1", f.completeCalls, f.abortCalls)
			}
			assertNoGoroutineLeak(t, client, before)
		})
	}
}

// assertNoGoroutineLeak waits for the goroutine count to drop back to before,
// after closing the client's idle connections.
func assertNoGoroutineLeak(t *testing.T, client Client, before int) {
	t.Helper()
	client.transport.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("goroutines: %d before, %d after\n%s", before, runtime.NumGoroutine(), buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(10 * time.Millisecond)
	}
}
