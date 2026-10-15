package router

import (
	"encoding/json"
	"testing"

	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
)

func TestUserLifecycleSwagger(t *testing.T) {
	doc := readAPI(t)
	for _, tc := range []struct {
		name string
		dto  any
	}{
		{"ChangeUserStatusRequest", accounthttp.ChangeUserStatusRequest{}},
		{"DeleteUserRequest", accounthttp.DeleteUserRequest{}},
		{"UserLifecycleResponse", accounthttp.UserLifecycleResponse{}},
	} {
		schema, ok := doc.Definitions["account_http."+tc.name]
		if !ok || schema.Type != "object" {
			t.Fatal("missing schema", tc.name)
		}
		encoded, err := json.Marshal(tc.dto)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != len(schema.Properties) {
			t.Fatal("DTO mismatch", tc.name, err)
		}
		for field := range fields {
			if _, ok := schema.Properties[field]; !ok {
				t.Fatal("undocumented field", tc.name, field)
			}
		}
	}
	for _, tc := range []struct{ method, path string }{{"post", "/api/v1/admin/users/{id}/status"}, {"delete", "/api/v1/admin/users/{id}"}} {
		op := doc.Paths[tc.path][tc.method]
		if op.Responses["200"].Schema.Ref != "#/definitions/account_http.UserLifecycleResponse" {
			t.Fatal("response mismatch", tc.path)
		}
		for _, status := range []string{"400", "401", "403", "404", "409", "503"} {
			if op.Responses[status].Schema.Ref != "#/definitions/httpx.ErrorResponse" {
				t.Fatal("missing failure", tc.path, status)
			}
		}
	}
}
