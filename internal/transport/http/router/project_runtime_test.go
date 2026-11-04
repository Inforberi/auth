package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	tokennativehttp "github.com/Inforberi/financial-intelligence/internal/auth/token/native/transport/http"
)

func TestProjectRouteProfilesAndAllowlist(t *testing.T) {
	called := 0
	endpoint := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called++; w.WriteHeader(204) })
	session := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := r.Cookie("__Host-session"); err != nil {
				w.WriteHeader(401)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	native := tokennativehttp.NewNative(tokennativehttp.NativeServices{}, nil)
	h, err := NewProjectRoutes("https://alpha.auth.test", []ProjectRoute{
		{Method: "POST", Path: "/login", Protection: "browser", Handler: endpoint},
		{Method: "GET", Path: "/callback", Protection: "callback", Handler: endpoint},
		{Method: "POST", Path: "/exchange", Protection: "session_no_refresh", Handler: endpoint},
		{Method: "GET", Path: "/me", Protection: "session", Handler: endpoint},
		{Method: "POST", Path: "/logout", Protection: "session_logout", Handler: endpoint},
		{Method: "POST", Path: "/native", Protection: "native", Handler: endpoint},
		{Method: "OPTIONS", Path: "/native", Protection: "native", Handler: endpoint},
	}, ProjectRouteProtection{Session: session, SessionNoRefresh: session, SessionLogout: session, Native: native.Protect})
	require.NoError(t, err)
	for _, test := range []struct {
		method, path, origin, cookie string
		want                         int
	}{
		{"POST", "/login", "", "", 403},
		{"POST", "/login", "https://beta.auth.test", "", 403},
		{"POST", "/login", "https://alpha.auth.test", "", 204},
		{"GET", "/callback", "", "", 204},
		{"GET", "/callback", "https://beta.auth.test", "", 403},
		{"POST", "/exchange", "https://alpha.auth.test", "", 401},
		{"POST", "/exchange", "https://alpha.auth.test", "__Host-session=opaque", 204},
		{"GET", "/me", "", "", 401},
		{"GET", "/me", "", "__Host-session=opaque", 204},
		{"GET", "/me", "https://beta.auth.test", "__Host-session=opaque", 403},
		{"POST", "/logout", "", "__Host-session=opaque", 403},
		{"POST", "/logout", "https://alpha.auth.test", "", 401},
		{"POST", "/logout", "https://alpha.auth.test", "__Host-session=opaque", 204},
		{"POST", "/native", "", "", 204},
		{"POST", "/native", "https://alpha.auth.test", "", 403},
		{"POST", "/native", "", "__Host-session=opaque", 400},
		{"OPTIONS", "/native", "", "", 403},
		{"POST", "/api/v1/admin/auth/login/email", "https://alpha.auth.test", "", 404},
		{"POST", "/api/v1/setup/start", "https://alpha.auth.test", "", 404},
	} {
		t.Run(test.method+test.path+test.origin+test.cookie, func(t *testing.T) {
			r := httptest.NewRequest(test.method, test.path, nil)
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			if test.cookie != "" {
				r.Header.Set("Cookie", test.cookie)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			require.Equal(t, test.want, w.Code)
			require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
		})
	}
	require.Equal(t, 6, called)
}

func TestProjectRoutesFailClosedForMissingProtection(t *testing.T) {
	for _, protection := range []string{"session", "session_no_refresh", "session_logout", "native", "unknown"} {
		_, err := NewProjectRoutes("https://alpha.auth.test", []ProjectRoute{{Method: "POST", Path: "/probe", Protection: protection, Handler: http.NotFoundHandler()}}, ProjectRouteProtection{})
		require.Error(t, err)
	}
}
