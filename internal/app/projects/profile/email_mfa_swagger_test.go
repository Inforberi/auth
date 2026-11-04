package profile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/docs/api/generated"
)

func TestProjectEmailMFASwaggerParity(t *testing.T) {
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	require.NoError(t, json.Unmarshal([]byte(docs.SwaggerInfo.ReadDoc()), &document))
	p := &ProjectProfile{states: map[string]ProjectFeatureState{}}
	for _, feature := range []string{"email_mfa", "email_mfa_login", "mfa_settings", "native_email_mfa"} {
		p.state(feature, "")
	}
	isEmailMFA := func(path string) bool {
		return path == "/api/v1/auth/mfa/email" || strings.HasPrefix(path, "/api/v1/auth/mfa/email/") ||
			strings.HasPrefix(path, "/api/v1/auth/native/mfa/email/") || path == "/api/v1/admin/auth/settings/mfa/email"
	}
	routes := map[string]bool{}
	for _, route := range p.RoutePlan() {
		if route.Method == "OPTIONS" || !isEmailMFA(route.Path) {
			continue
		}
		method := strings.ToLower(route.Method)
		require.Contains(t, document.Paths[route.Path], method, route.Path)
		routes[method+" "+route.Path] = true
	}
	documented := map[string]bool{}
	for path, methods := range document.Paths {
		if isEmailMFA(path) {
			for method := range methods {
				documented[method+" "+path] = true
			}
		}
	}
	require.Len(t, routes, 11)
	require.Equal(t, documented, routes, "project-only Swagger must match the actual profile plan in both directions")
}
