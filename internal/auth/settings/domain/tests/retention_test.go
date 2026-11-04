package domain_test

import (
	"errors"
	"testing"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestRetentionPolicy(t *testing.T) {
	base := settingsdomain.RetentionPolicy{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180}
	if err := base.Validate(); err != nil || base.Shortens(base) {
		t.Fatal(err)
	}
	for _, days := range []int{-1, 0, settingsdomain.MaxRetentionDays + 1} {
		for field := range 3 {
			p := base
			switch field {
			case 0:
				p.EmailReservationDays = days
			case 1:
				p.SessionDays = days
			case 2:
				p.SecurityAuditDays = days
			}
			if !errors.Is(p.Validate(), settingsdomain.ErrInvalidRetention) {
				t.Fatal("invalid period accepted", p)
			}
		}
	}
	for field := range 3 {
		p := base
		switch field {
		case 0:
			p.EmailReservationDays--
		case 1:
			p.SessionDays--
		case 2:
			p.SecurityAuditDays--
		}
		if !p.Shortens(base) {
			t.Fatal("missing shortening", p)
		}
	}
	if err := (settingsdomain.RetentionPolicy{EmailReservationDays: 1, SessionDays: settingsdomain.MaxRetentionDays, SecurityAuditDays: settingsdomain.MaxRetentionDays}).Validate(); err != nil {
		t.Fatal(err)
	}
}
