package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestLoginByEmail_ServiceErrors(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		statusCode   int
		exceptedCode string
	}{
		{
			"invalid email or password",
			passwordmodel.ErrInvalidEmailOrPassword,
			http.StatusBadRequest,
			errInvalidCredentials.code,
		},
		{
			"internal err",
			errors.New("internal error"),
			http.StatusBadRequest,
			errInternalError.code,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &mockPasswordService{}
			logger := zap.NewNop()

			req := httptest.NewRequest(
				http.MethodPost,
				"/auth/login/email",
				strings.NewReader(`{
							"email":"test@mail.ru",
							"password":"Password12345"
					}`),
			)

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "test-agent")
			req.RemoteAddr = "127.0.0.1:12345"

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Type", "application/json")
			rw := httptest.NewRecorder()

			service.On(
				"Login",
				req.Context(),
				passwordmodel.LoginInput{
					Email:     "test@mail.ru",
					Password:  "Password12345",
					UserAgent: "test-agent",
					IP:        "127.0.0.1",
				},
			).Return(
				nil,
				tt.err,
			)

			handler := New(service, logger)

			handler.LoginByEmail(rw, req)

			var resp map[string]interface{}

			err := json.Unmarshal(rw.Body.Bytes(), &resp)
			assert.NoError(t, err)

			code, ok := resp["code"].(string)
			assert.True(t, ok, "code should be string")

			assert.Equal(t, tt.exceptedCode, code)
		})
	}
}
