package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestServeFailure(t *testing.T) {
	failure := errors.New("listener failed")
	srv := &http.Server{ReadHeaderTimeout: time.Second}
	err := run(t.Context(), zap.NewNop(), srv, func() error { return failure })
	if !errors.Is(err, failure) {
		t.Fatalf("serve error lost: %v", err)
	}
}

func TestShutdownDeadlineClosesActiveConnection(t *testing.T) {
	started, finished := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(finished)
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Timeout = 3 * time.Second
	response := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		if err != nil {
			response <- err
			return
		}
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		response <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := shutdown(ctx, zap.NewNop(), srv.Config, 20*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected independent shutdown deadline: %v", err)
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("connection was not closed after deadline")
	}
	select {
	case err := <-response:
		if err == nil {
			t.Fatal("active request should be interrupted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not finish")
	}
}
