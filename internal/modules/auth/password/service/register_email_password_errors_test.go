package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRegister_EmailPasswordErrors(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		password string
	}{
		{name: "Invalid email", email: "test", password: "Test12345"},
		{name: "Invalid password", email: "test@mail.ru", password: "Test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockPasswordRepo{}
			session := &mockSession{}
			hasher := &mockHasher{}

			svc := newTestService(repo, session, hasher)

			registerResult, err := svc.Register(
				context.Background(),
				tt.email,
				tt.password,
				"mobile",
				"12345",
			)

			assert.Error(t, err)
			assert.Nil(t, registerResult)

			repo.AssertNotCalled(t, "ExistsByEmail", mock.Anything, mock.Anything)
			repo.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything, mock.Anything)
			hasher.AssertNotCalled(t, "GenerateHash", mock.Anything)
			session.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
