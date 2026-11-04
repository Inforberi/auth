package browser

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

func TestProfileUnlinkRequiresReadyPasswordFallback(t *testing.T) {
	ready := false
	profile := &binding{Endpoints: projectprofile.Endpoints{Available: func(feature string) bool { return feature == "password" && ready }}}
	called := 0
	handler := profile.requirePasswordFallback(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	})
	ready = false
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest("DELETE", "/api/v1/auth/google/link", nil))
	require.Equal(t, 409, w.Code)
	require.Zero(t, called)
	ready = true
	w = httptest.NewRecorder()
	handler(w, httptest.NewRequest("DELETE", "/api/v1/auth/google/link", nil))
	require.Equal(t, 204, w.Code)
	require.Equal(t, 1, called)
}
