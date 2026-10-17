package domain

import (
	"errors"
	"testing"
)

func TestRetentionPolicy(t *testing.T) {
	base := RetentionPolicy{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180}
	if err := base.Validate(); err != nil || base.Shortens(base) {
		t.Fatal(err)
	}
	for _, days := range []int{-1, 0, MaxRetentionDays + 1} {
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
			if !errors.Is(p.Validate(), ErrInvalidRetention) {
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
	if err := (RetentionPolicy{EmailReservationDays: 1, SessionDays: MaxRetentionDays, SecurityAuditDays: MaxRetentionDays}).Validate(); err != nil {
		t.Fatal(err)
	}
}
