package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func TestProjectFrontendPreflightUsesProjectPolicy(t *testing.T) {
	const origin = "https://auth.example.test"
	const frontend = "https://app.example.test"
	handler, err := NewProjectRoutes(origin, []ProjectRoute{
		{Method: http.MethodPost, Path: "/login", Protection: "browser", Handler: http.NotFoundHandler()},
		{Method: http.MethodPost, Path: "/service", Protection: "service", Handler: http.NotFoundHandler()},
	}, ProjectRouteProtection{Browser: middleware.OriginConfig{PolicySource: func(context.Context) (middleware.OriginConfig, error) {
		return middleware.OriginConfig{AllowedOrigins: []string{frontend}, CORSEnabled: true}, nil
	}}})
	require.NoError(t, err)
	for _, tc := range []struct {
		path, origin, method string
		status               int
	}{
		{"/login", frontend, http.MethodPost, http.StatusNoContent},
		{"/login", origin, http.MethodPost, http.StatusForbidden},
		{"/login", frontend, http.MethodDelete, http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodOptions, origin+tc.path, nil)
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Access-Control-Request-Method", tc.method)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		require.Equal(t, tc.status, w.Code)
		if tc.status == http.StatusNoContent {
			require.Equal(t, frontend, w.Header().Get("Access-Control-Allow-Origin"))
		} else {
			require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
		}
	}
}
