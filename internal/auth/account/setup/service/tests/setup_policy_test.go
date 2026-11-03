package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountsetup "github.com/Inforberi/financial-intelligence/internal/auth/account/setup/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestSetupMFAMode(t *testing.T) {
	for _, mode := range []settingsdomain.MFAMode{settingsdomain.MFAOptional, settingsdomain.MFAAdministrators, settingsdomain.MFARequired} {
		t.Run(string(mode), func(t *testing.T) {
			s, f, operator := setupServiceFixture(t)
			start, err := s.Start(context.Background(), accountsetup.SetupStartInput{OperatorSecret: operator, Email: "owner@example.test", Password: "Validpass1", MFAMode: mode})
			if err != nil {
				t.Fatal(err)
			}
			_, after, _ := strings.Cut(f.body, "<strong>")
			code, _, _ := strings.Cut(after, "</strong>")
			input := accountsetup.SetupCompleteInput{OperatorSecret: operator, Token: start.Token, EmailCode: code}
			optional := mode == settingsdomain.MFAOptional
			if optional {
				if start.Secret != "" || start.URI != "" || f.generated != 0 {
					t.Fatal("optional setup generated a factor")
				}
				input.TOTP = "123456"
			} // A required intent cannot be completed by omitting TOTP.
			if _, err := s.Complete(context.Background(), input); !errors.Is(err, domain.ErrSetupInvalid) {
				t.Fatal("wrong factor shape accepted", err)
			}
			if optional {
				input.TOTP = ""
			} else {
				input.TOTP = "123456"
			}
			result, err := s.Complete(context.Background(), input)
			if err != nil || f.account == nil || f.account.MFAMode != mode {
				t.Fatal("lost pinned mode", err)
			}
			if optional && (len(result.RecoveryCodes) != 0 || len(f.account.Factor) != 0 || len(f.account.RecoveryDigests) != 0 || f.matched != 0) {
				t.Fatal("optional setup created unused factor data")
			}
			if !optional && (len(result.RecoveryCodes) != 10 || len(f.account.Factor) == 0) {
				t.Fatal("required enrollment incomplete")
			}
		})
	}
}

func TestSetupInvalidModeBeforeHash(t *testing.T) {
	s, f, operator := setupServiceFixture(t)
	_, err := s.Start(context.Background(), accountsetup.SetupStartInput{OperatorSecret: operator, Email: "owner@example.test", Password: "Validpass1", MFAMode: "disabled"})
	if !errors.Is(err, settingsdomain.ErrInvalidMFAPolicy) || f.hashes != 0 || f.saves != 0 || f.mails != 0 {
		t.Fatal("invalid mode produced side effects", err)
	}
}
