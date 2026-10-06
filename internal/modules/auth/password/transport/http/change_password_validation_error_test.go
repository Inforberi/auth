package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/transport/http"
)

func TestChangePassword_ValidationError(t *testing.T) {
	service := &mockPasswordService{}
	logger := zap.NewNop()
	handler := New(service, logger)
	auth := sessionhttp.Auth{UserID: userID, TokenHash: tokenHash}

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
			name:           "invalid json",
			expectedStatus: http.StatusBadRequest,
			body:           `{"oldPassword":"oldPassword1", "newPassword":"newPassword1", "confirmPassword":"confirmPassword"`,
			expectedCode:   errInvalidJSON.code,
		},
		{
			name:           "empty old password",
			expectedStatus: http.StatusBadRequest,
			body:           `{"oldPassword":"", "newPassword":"newPassword1", "confirmPassword":"confirmPassword"}`,
			expectedCode:   "empty_old_password",
		},
		{
			name:           "empty new password",
			expectedStatus: http.StatusBadRequest,
			body:           `{"oldPassword":"oldPassword1", "newPassword":"", "confirmPassword":"confirmPassword"}`,
			expectedCode:   "empty_new_password",
		},
		{
			name:           "empty confirm password",
			expectedStatus: http.StatusBadRequest,
			body:           `{"oldPassword":"oldPassword1", "newPassword":"newPassword1", "confirmPassword":""}`,
			expectedCode:   "empty_confirm_password",
		},
		{
			name:           "mismatch password",
			expectedStatus: http.StatusBadRequest,
			body:           `{"oldPassword":"oldPassword1", "newPassword":"newPassword1", "confirmPassword":"newPassword"}`,
			expectedCode:   "password_mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(sessionhttp.SetAuthContext(req.Context(), auth))

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Type", "application/json")
			rw := httptest.NewRecorder()
			handler.ChangePassword(rw, req)

			assert.Equal(t, tt.expectedStatus, rw.Code)

			var resp map[string]interface{}

			err := json.Unmarshal(rw.Body.Bytes(), &resp)
			assert.NoError(t, err)

			code, ok := resp["code"].(string)
			assert.True(t, ok, "code should be string")
			assert.Equal(t, tt.expectedCode, code)
		})
	}
}
