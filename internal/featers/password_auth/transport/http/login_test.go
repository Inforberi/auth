package password_http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

var (
	user      = domain.UserID("user-1")
	token     = "RawToken"
	expiresAt = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
)

func TestLoginByEmail_Success(t *testing.T) {
	service := &mockPasswordService{}

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

	rr := httptest.NewRecorder()

	service.On(
		"Login",
		req.Context(),
		password_domain.LoginInput{
			Email:     "test@mail.ru",
			Password:  "Password12345",
			UserAgent: "test-agent",
			IP:        "127.0.0.1",
		},
	).Return(
		&password_domain.LoginResult{
			UserID:    user,
			Token:     token,
			ExpiresAt: expiresAt,
		},
		nil,
	)

	handler := New(service, zap.NewNop())

	handler.LoginByEmail(rr, req)

	var response LoginByEmailResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "ok", response.Status)

	service.AssertExpectations(t)
}

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

func TestLoginByEmail_ServiceErrors(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		statusCode   int
		exceptedCode string
	}{
		{
			"invalid email or password",
			password_domain.ErrInvalidEmailOrPassword,
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

			rw := httptest.NewRecorder()

			service.On(
				"Login",
				req.Context(),
				password_domain.LoginInput{
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
