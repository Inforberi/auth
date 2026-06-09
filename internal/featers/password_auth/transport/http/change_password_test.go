package password_http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/httpx"
	"go.uber.org/zap"
)

const (
	userID    = domain.UserID("user-1")
	tokenHash = "tokenhash123"
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
		}
		`,
		),
	)

	w := httptest.NewRecorder()

	handler := New(service, logger)

}
