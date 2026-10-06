package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
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

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

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
		&passwordmodel.LoginResult{
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
