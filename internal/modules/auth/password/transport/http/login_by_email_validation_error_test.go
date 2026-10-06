package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestLoginByEmail_ValidationError(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		exceptedCode string
		body         string
	}{
		{
			"invalid json",
			http.StatusBadRequest,
			errInvalidJSON.code,
			`
				"email":"test@mail.ru",
				"password":"Password12345"
			}`,
		},
		{
			"empty email",
			http.StatusBadRequest,
			errEmailRequired.code,
			`{
				"email":"",
				"password":"Password12345"
			}`,
		},
		{
			"empty password",
			http.StatusBadRequest,
			errPasswordRequired.code,
			`{
				"email":"test@mail.ru",
				"password":""
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &mockPasswordService{}
			logger := zap.NewNop()

			handler := New(service, logger)

			req := httptest.NewRequest(
				http.MethodPost,
				"/auth/login/email",
				strings.NewReader(tt.body),
			)

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Type", "application/json")
			rw := httptest.NewRecorder()

			handler.LoginByEmail(rw, req)

			var resp map[string]interface{}
			err := json.Unmarshal(rw.Body.Bytes(), &resp)
			assert.NoError(t, err)

			code, ok := resp["code"].(string)
			assert.True(t, ok, "code should be string")

			assert.Equal(t, tt.statusCode, rw.Code)
			assert.Equal(t, tt.exceptedCode, code)
		})
	}
}
