package router

import (
	"encoding/json"
	"testing"

	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
)

func TestUserDirectorySwagger(t *testing.T) {
	doc := readAPI(t)
	for _, tc := range []struct {
		name string
		dto  any
	}{
		{"UserSummaryResponse", accounthttp.UserSummaryResponse{}},
		{"UserDetailResponse", accounthttp.UserDetailResponse{}},
		{"UserPageResponse", accounthttp.UserPageResponse{}},
		{"UserContactResponse", accounthttp.UserContactResponse{}},
		{"UserRoleResponse", accounthttp.UserRoleResponse{}},
	} {
		schema, ok := doc.Definitions["account_http."+tc.name]
		if !ok || schema.Type != "object" {
			t.Fatal("missing DTO schema", tc.name)
		}
		encoded, err := json.Marshal(tc.dto)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != len(schema.Properties) {
			t.Fatal("DTO field mismatch", tc.name, err)
		}
		for field := range fields {
			if _, exists := schema.Properties[field]; !exists {
				t.Fatal("undocumented field", tc.name, field)
			}
		}
	}
	for _, tc := range []struct{ path, response string }{
		{"/api/v1/admin/users", "UserPageResponse"}, {"/api/v1/admin/users/{id}", "UserDetailResponse"},
	} {
		op := doc.Paths[tc.path]["get"]
		if op.Responses["200"].Schema.Ref != "#/definitions/account_http."+tc.response {
			t.Fatal("incorrect response schema", tc.path)
		}
		for _, status := range []string{"400", "401", "403", "503"} {
			if op.Responses[status].Schema.Ref != "#/definitions/httpx.ErrorResponse" {
				t.Fatal("missing failure schema", tc.path, status)
			}
		}
	}
}
