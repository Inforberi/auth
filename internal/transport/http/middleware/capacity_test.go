package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionBurst(t *testing.T) {
	started, release := make(chan struct{}, 2), make(chan struct{})
	var calls atomic.Int64
	h := Admission(CapacityConfig{MaxInFlight: 2, RequestTimeout: time.Second})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("missing deadline")
		}
		calls.Add(1)
		started <- struct{}{}
		<-release
		w.WriteHeader(204)
	}))
	var active sync.WaitGroup
	for range 2 {
		active.Go(func() { h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/auth/me", nil)) })
	}
	<-started
	<-started
	var burst sync.WaitGroup
	for range 1000 {
		burst.Go(func() {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/auth/me", nil))
			if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
				t.Error("overload not rejected", w.Code)
			}
		})
	}
	burst.Wait()
	if calls.Load() != 2 {
		t.Fatal("overload reached dependencies")
	}
	close(release)
	active.Wait()
}

func TestLivenessBypassesBusyAdmission(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	h := Admission(CapacityConfig{MaxInFlight: 1, RequestTimeout: time.Second})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/live" {
			close(started)
			<-release
		}
		w.WriteHeader(200)
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/busy", nil))
	}()
	<-started
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/health/live", nil))
	close(release)
	<-done
	if w.Code != 200 {
		t.Fatal("overload killed liveness")
	}
}
