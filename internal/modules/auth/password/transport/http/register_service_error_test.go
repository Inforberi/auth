package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestRegister_ServiceError(t *testing.T) {
	service := &mockPasswordService{}

	service.
		On(
			"Register",
			mock.Anything,
			"test@mail.ru",
			"Password123",
			mock.Anything,
			mock.Anything,
		).
		Return(
			nil,
			passwordmodel.ErrEmailAlreadyExists,
		)

	handler := New(service, zap.NewNop())

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth/register/email",
		strings.NewReader(`
			{
			"email":"test@mail.ru",
			"password":"Password123"
			}
	`,
		),
	)

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.Register(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
	service.AssertExpectations(t)
}
