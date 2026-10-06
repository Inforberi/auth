package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestLogin_InvalidEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		password string
	}{
		{
			name:     "empty email",
			email:    "",
			password: "Password12345",
		},
		{
			name:     "invalid email",
			email:    "invalid",
			password: "Password12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockPasswordRepo{}
			hasher := &mockHasher{}
			session := &mockSession{}

			svc := newTestService(repo, session, hasher)

			result, err := svc.Login(
				context.Background(),
				passwordmodel.LoginInput{
					Email:     tt.email,
					Password:  tt.password,
					UserAgent: "mobile",
					IP:        "127.0.0.1",
				},
			)

			assert.Error(t, err)
			assert.Nil(t, result)

			repo.AssertNotCalled(
				t,
				"FindByEmail",
				mock.Anything,
				mock.Anything,
			)

			hasher.AssertNotCalled(
				t,
				"Compare",
				mock.Anything,
				mock.Anything,
			)

			session.AssertNotCalled(
				t,
				"CreateSession",
				mock.Anything,
				mock.Anything,
				mock.Anything,
				mock.Anything,
			)
		})
	}
}
