package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func TestRegister_EmailRequired(t *testing.T) {
	service := &mockPasswordService{}
	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`{"password":"Password123"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.Register(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	service.AssertNotCalled(
		t,
		"Register",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}
