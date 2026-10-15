package router

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
)

func TestProvisioningSwaggerDTOs(t *testing.T) {
	doc := readAPI(t)
	for _, tc := range []struct {
		name string
		dto  any
	}{
		{"account_http.ProvisionRequest", accounthttp.ProvisionRequest{}},
		{"account_http.ReissueInvitationRequest", accounthttp.ReissueInvitationRequest{}},
		{"account_http.ProvisionResponse", accounthttp.ProvisionResponse{}},
		{"password_http.TemporaryProvisionRequest", passwordhttp.TemporaryProvisionRequest{}},
		{"password_http.TemporaryReissueRequest", passwordhttp.TemporaryReissueRequest{}},
		{"password_http.TemporaryIssueResponse", passwordhttp.TemporaryIssueResponse{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			schema, ok := doc.Definitions[tc.name]
			typ := reflect.TypeOf(tc.dto)
			if !ok || schema.Type != "object" || len(schema.Properties) != typ.NumField() {
				t.Fatal("DTO/schema field mismatch")
			}
			var required []string
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				name := strings.Split(field.Tag.Get("json"), ",")[0]
				want := "string"
				if field.Type.Kind() == reflect.Bool {
					want = "boolean"
				}
				if schema.Properties[name].Type != want {
					t.Fatal("wrong schema type", name)
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
	for _, tc := range []struct {
		path, request string
		create        bool
	}{
		{"/api/v1/admin/users", "account_http.ProvisionRequest", true},
		{"/api/v1/admin/users/{id}/invitation", "account_http.ReissueInvitationRequest", false},
		{"/api/v1/admin/users/temporary-password", "password_http.TemporaryProvisionRequest", true},
		{"/api/v1/admin/users/{id}/temporary-password", "password_http.TemporaryReissueRequest", false},
	} {
		op := doc.Paths[tc.path]["post"]
		var origin, body bool
		for _, p := range op.Parameters {
			if p.In == "header" && p.Name == "Origin" && p.Required {
				origin = true
			}
			if p.In == "body" && p.Required && p.Schema.Ref == "#/definitions/"+tc.request {
				body = true
			}
		}
		if !origin || !body || !slices.Equal(op.Consumes, []string{"application/json"}) {
			t.Fatal("missing Origin/JSON body", tc.path)
		}
		for _, status := range []string{"400", "401", "403", "409", "429", "503"} {
			if op.Responses[status].Schema.Ref != "#/definitions/httpx.ErrorResponse" {
				t.Fatal("missing error response", tc.path, status)
			}
		}
		if op.Responses["200"].Schema.Ref == "" || (tc.create && op.Responses["201"].Schema.Ref == "") {
			t.Fatal("missing replay/creation response", tc.path)
		}
	}
}
