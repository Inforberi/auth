package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func TestValidateSession_ErrFindSession(t *testing.T) {
	clock := &mockClock{}
	token := &mockTokenHash{}
	repo := &mockRepo{}

	token.On("Hash", "RawToken").Return("HashedToken")

	repo.On("FindSession", context.Background(), "HashedToken").Return(nil, sessionmodel.ErrSessionNotFound)

	svc := New(clock, repo, token, cfg)

	session, err := svc.ValidateSession(context.Background(), "RawToken")

	assert.Error(t, err)
	assert.ErrorIs(t, err, sessionmodel.ErrSessionNotFound)
	assert.Nil(t, session)

	clock.AssertNotCalled(t, "NowUTC")

	repo.AssertNotCalled(
		t,
		"UpdateSession",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)

	repo.AssertExpectations(t)

	token.AssertExpectations(t)
}
