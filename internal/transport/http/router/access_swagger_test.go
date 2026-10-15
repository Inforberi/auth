package router

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	accesshttp "github.com/Inforberi/financial-intelligence/internal/access/transport/http"
)

func TestAccessSwaggerDTOs(t *testing.T) {
	doc := readAPI(t)
	for _, tc := range []struct {
		name string
		dto  any
	}{
		{"CreateRoleRequest", accesshttp.CreateRoleRequest{}},
		{"UpdateRoleRequest", accesshttp.UpdateRoleRequest{}},
		{"AssignmentRequest", accesshttp.AssignmentRequest{}},
		{"AdministratorRequest", accesshttp.AdministratorRequest{}},
		{"AssignmentResponse", accesshttp.AssignmentResponse{}},
		{"RoleResponse", accesshttp.RoleResponse{}},
		{"RoleSummaryResponse", accesshttp.RoleSummaryResponse{}},
		{"RolePageResponse", accesshttp.RolePageResponse{}},
		{"AccessResponse", accesshttp.AccessResponse{}},
		{"PermissionCatalogResponse", accesshttp.PermissionCatalogResponse{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			schema, ok := doc.Definitions["access_http."+tc.name]
			if !ok || schema.Type != "object" {
				t.Fatal("missing DTO schema")
			}
			encoded, err := json.Marshal(tc.dto)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != len(schema.Properties) {
				t.Fatal("DTO field count differs from schema", err)
			}
			typ := reflect.TypeOf(tc.dto)
			var required []string
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				name := strings.Split(field.Tag.Get("json"), ",")[0]
				wantType := "string"
				switch field.Type.Kind() {
				case reflect.Int64:
					wantType = "integer"
				case reflect.Bool:
					wantType = "boolean"
				case reflect.Slice:
					wantType = "array"
				}
				if schema.Properties[name].Type != wantType {
					t.Fatalf("%s: schema type differs from JSON type", name)
				}
				if field.Tag.Get("binding") == "required" {
					required = append(required, name)
				}
			}
			slices.Sort(required)
			actual := slices.Clone(schema.Required)
			slices.Sort(actual)
			if !slices.Equal(actual, required) {
				t.Fatal("required fields differ", actual, required)
			}
		})
	}
}

func TestAccessSwaggerMutations(t *testing.T) {
	doc := readAPI(t)
	for _, tc := range []struct{ path, method, request string }{
		{"/api/v1/admin/roles", "post", "CreateRoleRequest"},
		{"/api/v1/admin/roles/{id}", "post", "UpdateRoleRequest"},
		{"/api/v1/admin/users/{id}/roles/{roleId}", "post", "AssignmentRequest"},
		{"/api/v1/admin/users/{id}/roles/{roleId}", "delete", "AssignmentRequest"},
	} {
		op := doc.Paths[tc.path][tc.method]
		var origin, body bool
		for _, parameter := range op.Parameters {
			if parameter.In == "header" && parameter.Name == "Origin" && parameter.Required {
				origin = true
			}
			if parameter.In == "body" && parameter.Required && parameter.Schema.Ref == "#/definitions/access_http."+tc.request {
				body = true
			}
		}
		if !origin || !body || !slices.Equal(op.Consumes, []string{"application/json"}) {
			t.Fatal("missing Origin, JSON or version body contract", tc)
		}
		for _, status := range []string{"400", "401", "403", "409", "503"} {
			if op.Responses[status].Schema.Ref != "#/definitions/httpx.ErrorResponse" {
				t.Fatal("missing public failure contract", tc, status)
			}
		}
	}
}
