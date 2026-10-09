package http

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/docs"
)

func TestSwaggerDocumentsClientErrors(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Description string `json:"description"`
			} `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal([]byte(docs.SwaggerInfo.ReadDoc()), &doc); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path   string
		errors []clientError
	}{
		{"/api/v1/auth/register/email", registerClientErrors},
		{"/api/v1/auth/login/email", loginClientErrors},
		{"/api/v1/auth/change-password", changePasswordErrors},
	} {
		for _, ce := range tc.errors {
			mapped := mapError(ce.err, tc.errors)
			description := doc.Paths[tc.path]["post"].Responses[strconv.Itoa(mapped.Status)].Description
			if !strings.Contains(description, mapped.Code) {
				t.Errorf("%s: undocumented %d %s", tc.path, mapped.Status, mapped.Code)
			}
		}
	}
}
