package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestMalformedCookieNeverReachesSessionStorage(t *testing.T) {
	for _, token := range []string{"", "bad", strings.Repeat("A", 44), strings.Repeat("A", 42) + "B", strings.Repeat("!", 43)} {
		service := &sessionStub{}
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		w := httptest.NewRecorder()
		New(service, zap.NewNop()).Auth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("malformed cookie accepted") })).ServeHTTP(w, r)
		if w.Code != 401 || service.calls != 0 {
			t.Fatal("malformed cookie reached SQL", w.Code, service.calls)
		}
	}
}
