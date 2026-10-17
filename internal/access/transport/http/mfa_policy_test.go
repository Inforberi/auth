package http

import (
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

func TestRoleMFAFieldIntent(t *testing.T) {
	svc := &captureService{}
	h := New(svc, zap.NewNop())
	mux := chi.NewRouter()
	mux.Post("/roles/{id}", h.UpdateRole)
	for _, tc := range []struct {
		field          string
		present, value bool
	}{
		{``, false, false}, {`,"mfaRequired":null`, false, false}, {`,"mfaRequired":false`, true, false}, {`,"mfaRequired":true`, true, true},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, accessRequest("POST", "/roles/33333333-3333-4333-8333-333333333333", `{"key":"reader","name":"Reader","expectedVersion":1`+tc.field+`}`))
		value := svc.update.MFARequired
		if w.Code != 200 || (value != nil) != tc.present || (value != nil && *value != tc.value) {
			t.Fatal("MFA update intent changed", w.Code, value)
		}
	}
	w := httptest.NewRecorder()
	before := svc.calls
	mux.ServeHTTP(w, accessRequest("POST", "/roles/33333333-3333-4333-8333-333333333333", `{"mfaRequired":"true"}`))
	if w.Code != 400 || svc.calls != before {
		t.Fatal("invalid policy shape reached service", w.Code)
	}
}
