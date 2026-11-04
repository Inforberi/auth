package router_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func TestProjectHostRoutingHasNoOperatorFallback(t *testing.T) {
	operator := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(201) })
	project := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })
	h := router.ProjectHosts("https://platform.example.test", operator, project)
	for host, want := range map[string]int{"platform.example.test": 201, "project.example.test": 404, "Platform.example.test": 404, "platform.example.test.attacker.test": 404} {
		r := httptest.NewRequest("GET", "https://"+host+"/api/v1/projects", nil)
		r.Header.Set("X-Forwarded-Host", "platform.example.test")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, want, w.Code)
	}
}

func TestProjectHostsWithoutProjectHandler(t *testing.T) {
	operator := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	w := httptest.NewRecorder()
	router.ProjectHosts("https://platform.example.test", operator, nil).ServeHTTP(w, httptest.NewRequest("GET", "https://platform.example.test", nil))
	require.Equal(t, 204, w.Code)
}
