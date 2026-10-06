package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/transport/http"
)

func TestChangePassword_Success(t *testing.T) {
	service := &mockPasswordService{}
	logger := zap.NewNop()

	auth := sessionhttp.Auth{
		UserID:    userID,
		TokenHash: tokenHash,
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/change-password",
		strings.NewReader(`
		{
			"oldPassword":"oldPassword1",
			"newPassword":"newPassword1",
			"confirmPassword":"newPassword1"
		}`),
	)

	req = req.WithContext(sessionhttp.SetAuthContext(req.Context(), auth))

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	service.On(
		"ChangePassword",
		req.Context(),
		auth.UserID,
		auth.TokenHash,
		oldPassword,
		newPassword,
	).Return(nil)

	handler := New(service, logger)
	handler.ChangePassword(rr, req)

	var response ChangePasswordResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)

	assert.NoError(t, err)
	assert.Equal(t, response, ChangePasswordResponse{
		Status: "ok",
	})
	assert.Equal(t, http.StatusOK, rr.Code)

	service.AssertExpectations(t)
}
