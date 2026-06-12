package password_http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
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
			req = req.WithContext(httpx.SetAuthContext(req.Context(), auth))

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

func TestChangePassword_NoAuth(t *testing.T) {
	service := &mockPasswordService{}
	logger := zap.NewNop()

	handler := New(service, logger)

	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(`{
		"oldPassword":"oldPassword1",
		"newPassword":"newPassword1",
		"confirmPassword":"newPassword1"
	}`))

	rw := httptest.NewRecorder()

	handler.ChangePassword(rw, req)

	assert.Equal(t, http.StatusUnauthorized, rw.Code)

	var resp map[string]interface{}

	err := json.Unmarshal(rw.Body.Bytes(), &resp)

	assert.NoError(t, err)
	assert.Equal(t, "unauthorized", resp["code"])
}

func TestChangePassword_ServiceError(t *testing.T) {
	auth := httpx.Auth{UserID: userID, TokenHash: tokenHash}

	tests := []struct {
		name         string
		statusCode   int
		expectedCode string
		err          error
	}{
		{
			"invalid email or password",
			http.StatusBadRequest,
			errInvalidEmailOrPassword.code,
			password_domain.ErrInvalidEmailOrPassword,
		},
		{
			"same password",
			http.StatusBadRequest,
			errSamePassword.code,
			password_domain.ErrSamePassword,
		},
		{
			"user not found",
			http.StatusNotFound,
			errNotFound.code,
			password_domain.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &mockPasswordService{}
			logger := zap.NewNop()

			req := httptest.NewRequest(
				http.MethodPost,
				"/auth/change-password",
				strings.NewReader(`
				{
					"oldPassword":"oldPassword1",
					"newPassword":"newPassword1",
					"confirmPassword":"newPassword1"
				}`))
			req.Header.Set("Content-type", "application/json")
			req = req.WithContext(httpx.SetAuthContext(req.Context(), auth))

			rw := httptest.NewRecorder()

			service.On(
				"ChangePassword",
				req.Context(),
				auth.UserID,
				auth.TokenHash,
				oldPassword,
				newPassword,
			).Return(tt.err)

			handler := New(service, logger)

			handler.ChangePassword(rw, req)

			var response map[string]interface{}
			err := json.Unmarshal(rw.Body.Bytes(), &response)
			assert.NoError(t, err)

			code, ok := response["code"].(string)
			assert.True(t, ok, "code should be string")
			assert.Equal(t, tt.expectedCode, code)

		})
	}
}
