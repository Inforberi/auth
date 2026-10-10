package httpx

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
)

type dependencyError struct{ secret string }

func (e *dependencyError) Error() string { return e.secret }

func TestMapError(t *testing.T) {
	limited := errors.New("limited")
	invalid := errors.New("invalid")
	fallback := Failure{Status: 500, Code: "internal_error", Message: "internal error"}
	rules := []ErrorRule{
		{Target: limited, Response: Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
		MatchError(invalid, 400, "invalid_input", "invalid input"),
		{Match: func(err error) bool {
			var typed *dependencyError
			return errors.As(err, &typed)
		}, Response: Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"}},
	}
	for _, tc := range []struct {
		name string
		err  error
		want Failure
	}{
		{"sentinel", limited, rules[0].Response},
		{"wrapped sentinel", fmt.Errorf("private: %w", invalid), rules[1].Response},
		{"typed", &dependencyError{"secret"}, rules[2].Response},
		{"wrapped typed", fmt.Errorf("private: %w", &dependencyError{"secret"}), rules[2].Response},
		{"rule priority", errors.Join(invalid, limited), rules[0].Response},
		{"unknown", errors.New("limited"), fallback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MapError(tc.err, rules, fallback); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
	for _, status := range []int{500, 503} {
		if got := MapError(errors.New("private"), nil, Failure{Status: status}); got.Status != status {
			t.Fatal("operation fallback ignored")
		}
	}
}

func TestRespondErrorSafeLogging(t *testing.T) {
	for _, status := range []int{400, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			fallbackCore, fallbackLogs := observer.New(zap.DebugLevel)
			log := zap.New(core).With(zap.String("request_id", "generated-id"))
			r := httptest.NewRequest("POST", "/?token=secret-token", strings.NewReader("secret-password"))
			r.Header.Set("User-Agent", "secret-agent")
			r.Header.Set("Authorization", "Bearer secret-bearer")
			r = r.WithContext(logger.WithContext(r.Context(), log))
			w := httptest.NewRecorder()
			failure := Failure{Status: status, Code: "public_code", Message: "public message"}
			RespondError(w, r, zap.New(fallbackCore), "confirm", errors.New("secret-dsn secret-mail"), nil, failure)
			if w.Code != status || w.Body.String() != "{\"code\":\"public_code\",\"message\":\"public message\"}\n" {
				t.Fatal(w.Code, w.Body.String())
			}
			if logs.Len() != 1 || fallbackLogs.Len() != 0 {
				t.Fatal("expected one error log on the request logger")
			}
			entry := logs.All()[0]
			fields := entry.ContextMap()
			if len(fields) != 4 || fields["request_id"] != "generated-id" || fields["operation"] != "confirm" || fields["error_code"] != "public_code" || fields["status"] != int64(status) {
				t.Fatal(fields)
			}
			wantLevel := zap.WarnLevel
			if status >= 500 {
				wantLevel = zap.ErrorLevel
			}
			if entry.Level != wantLevel || strings.Contains(fmt.Sprint(entry), "secret") {
				t.Fatal("unsafe or incorrect error log")
			}
		})
	}
}

func TestWriteFailureHeaders(t *testing.T) {
	failure := Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"900"}}}
	for range 2 {
		w := httptest.NewRecorder()
		w.Header().Set("Retry-After", "wrong")
		w.Header().Set("Cache-Control", "no-store")
		WriteFailure(w, failure)
		if w.Code != 429 || w.Header().Get("Retry-After") != "900" || len(w.Header().Values("Retry-After")) != 1 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code, w.Header())
		}
		w.Header().Set("Retry-After", "changed")
	}
	if failure.Headers.Get("Retry-After") != "900" {
		t.Fatal("shared rule mutated by response writer")
	}
}
