package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

type resetClock struct{}

func (resetClock) NowUTC() time.Time { return now }

func TestForgotPasswordDelivery(t *testing.T) {
	for _, fail := range []bool{false, true} {
		repo := &mockPasswordRepo{}
		tm := &mockTokenManager{}
		redis := &mockRedisRepo{}
		mail := &mockMailer{}
		repo.On("FindByEmail", mock.Anything, "test@example.com").Return(&passwordmodel.FindByEmailResult{UserID: accountmodel.UserID("u")}, nil)
		tm.On("GenerateToken", []int{32}).Return("raw", nil)
		tm.On("Hash", "raw").Return("hash")
		redis.On("SaveResetToken", mock.Anything, "hash", accountmodel.UserID("u"), time.Hour).Return(nil)
		var delivery error
		if fail {
			delivery = errors.New("delivery failed")
		}
		mail.On("Send", "test@example.com", "Сброс пароля", mock.AnythingOfType("string")).Return(delivery)
		svc := New(repo, nil, nil, resetClock{}, tm, redis, passwordmodel.Config{ResetTokenTTL: time.Hour, ResetURL: "https://example.com/reset"}, mail)
		err := svc.ForgotPassword(context.Background(), "test@example.com")
		if fail && !errors.Is(err, delivery) {
			t.Fatal("delivery error lost")
		}
		if !fail && err != nil {
			t.Fatal(err)
		}
		mail.AssertExpectations(t)
		redis.AssertExpectations(t)
	}
}
