package password_http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

const (
	userID      = domain.UserID("user-1")
	tokenHash   = "tokenhash123"
	oldPassword = "oldPassword1"
	newPassword = "newPassword1"
)

func TestChangePassword_Success(t *testing.T) {
	service := &mockPasswordService{}
	logger := zap.NewNop()

	auth := httpx.Auth{
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

	req = req.WithContext(httpx.SetAuthContext(req.Context(), auth))

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

func TestChangePassword_ValidationError(t *testing.T) {
	service := &mockPasswordService{}
	logger := zap.NewNop()
	handler := New(service, logger)
	auth := httpx.Auth{UserID: userID, TokenHash: tokenHash}

	service.On(
		"ChangePassword",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Maybe().Return(nil)

	tests := []struct {
		name           string
		expectedStatus int
		body           string
		expectedCode   string
	}{
		{
			name:           "empty old password",
			expectedStatus: http.StatusBadRequest,
			body:           `{"oldPassword":"", "newPassword":"newPassword1", "confirmPassword":"confirmPassword"}`,
			expectedCode:   "empty_old_password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(httpx.SetAuthContext(req.Context(), auth))

			rr := httptest.NewRecorder()
			handler.ChangePassword(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			var resp map[string]interface{}

			err := json.Unmarshal(rr.Body.Bytes(), &resp)
			assert.NoError(t, err)
			// приведение к строке и сравнение с ожидаемым кодом
			code, ok := resp["code"].(string)
			assert.True(t, ok, "code should be string")
			assert.Equal(t, tt.expectedCode, code)
		})
	}
}
