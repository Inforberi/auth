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
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/transport/http"
)

func TestChangePassword_ServiceError(t *testing.T) {
	auth := sessionhttp.Auth{UserID: userID, TokenHash: tokenHash}

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
			passwordmodel.ErrInvalidEmailOrPassword,
		},
		{
			"same password",
			http.StatusBadRequest,
			errSamePassword.code,
			passwordmodel.ErrSamePassword,
		},
		{
			"user not found",
			http.StatusNotFound,
			errNotFound.code,
			passwordmodel.ErrNotFound,
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
			req = req.WithContext(sessionhttp.SetAuthContext(req.Context(), auth))

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Type", "application/json")
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
