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

func TestChangePassword_NoAuth(t *testing.T) {
	service := &mockPasswordService{}
	logger := zap.NewNop()

	handler := New(service, logger)

	req := httptest.NewRequest(http.MethodPost, "/auth/change-password", strings.NewReader(`{
		"oldPassword":"oldPassword1",
		"newPassword":"newPassword1",
		"confirmPassword":"newPassword1"
	}`))

	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()

	handler.ChangePassword(rw, req)

	assert.Equal(t, http.StatusUnauthorized, rw.Code)

	var resp map[string]interface{}

	err := json.Unmarshal(rw.Body.Bytes(), &resp)

	assert.NoError(t, err)
	assert.Equal(t, "unauthorized", resp["code"])
}
