package service

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

func TestSecurityNoticeKinds(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "mfa:v1")
	require.NoError(t, err)
	for _, event := range []string{"telegram_factor_enabled", "telegram_factor_replaced", "telegram_factor_disabled"} {
		t.Run(event, func(t *testing.T) {
			payload, err := SealNotice(cipher, "owner@example.com", event, "", time.Now())
			require.NoError(t, err)
			repo := &recoveryDeliveryStub{job: &domain.SecurityDelivery{Payload: payload}}
			mail := &recoveryMailStub{}
			worker, err := NewSecurityDelivery(repo, cipher, mail)
			require.NoError(t, err)
			processed, err := worker.DeliverOne(t.Context())
			require.NoError(t, err)
			require.True(t, processed && repo.sent)
			require.Equal(t, "owner@example.com", mail.to)
			require.NotContains(t, mail.body, "href=")
		})
	}
	for _, notice := range []securityNotice{
		{To: "owner@example.com", Kind: "unrecognized", At: time.Now()},
		{To: "owner@example.com\r\nBcc: attacker@example.com", Kind: "telegram_factor_enabled", At: time.Now()},
		{To: "owner@example.com", Kind: "telegram_factor_enabled"},
		{To: "owner@example.com", Kind: "telegram_factor_enabled", RequestID: "unexpected", At: time.Now()},
	} {
		_, err := securityNoticeBody(notice)
		require.ErrorIs(t, err, domain.ErrSecurityDelivery)
		require.False(t, strings.Contains(err.Error(), notice.To))
	}
}
