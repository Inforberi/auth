package router

import (
	"strings"
	"testing"
)

func TestSwaggerSDKContract(t *testing.T) {
	doc := readAPI(t)
	seen := make(map[string]string)
	for path, methods := range doc.Paths {
		for method, operation := range methods {
			endpoint := method + " " + path
			switch {
			case operation.OperationID == "":
				t.Errorf("%s has no operationId", endpoint)
			case seen[operation.OperationID] != "":
				t.Errorf("%s and %s share operationId %q", endpoint, seen[operation.OperationID], operation.OperationID)
			default:
				seen[operation.OperationID] = endpoint
			}
			for _, segment := range strings.Split(path, "/") {
				if !strings.HasPrefix(segment, "{") || !strings.HasSuffix(segment, "}") {
					continue
				}
				name := segment[1 : len(segment)-1]
				found := false
				for _, parameter := range operation.Parameters {
					found = found || parameter.Name == name && parameter.In == "path" && parameter.Required
				}
				if !found {
					t.Errorf("%s lacks a required path parameter %q", endpoint, name)
				}
			}
		}
	}
	for _, test := range []struct {
		method, path, scheme string
	}{
		{"get", "/api/v1/auth/me", "SessionCookie"},
		{"post", "/api/v1/auth/token/exchange", "SessionCookie"},
		{"post", "/api/v1/internal/auth/token/introspect", "ServiceBasic"},
		{"post", "/api/v1/setup/start", "SetupToken"},
	} {
		operation := doc.Paths[test.path][test.method]
		if len(operation.Security) != 1 {
			t.Errorf("%s has no explicit %s security requirement", test.path, test.scheme)
			continue
		}
		if _, ok := operation.Security[0][test.scheme]; !ok {
			t.Errorf("%s has no %s security requirement", test.path, test.scheme)
		}
	}
}
