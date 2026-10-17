package service

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func TestNativeEmailCodeBinding(t *testing.T) {
	s, f, cipher := otpFixture(t)
	scope := []accessdomain.PermissionKey{"orders.write", "orders.read"}
	requested, err := s.RequestNative(t.Context(), "user@example.test", "::ffff:192.0.2.1", mfaservice.NativeTarget{Audience: "orders", Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	scope[0] = "unrelated.permission"
	if !slices.Equal(f.challenge.NativeScope, []accessdomain.PermissionKey{"orders.read", "orders.write"}) || f.challenge.NativeAudience != "orders" || f.challenge.Digest == cipher.Digest("binding:"+requested.Binding) {
		t.Fatal("mutable target or browser namespace retained")
	}
	plain, err := cipher.Open(f.challenge.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var mail codeMail
	if err := json.Unmarshal(plain, &mail); err != nil {
		t.Fatal(err)
	}
	start := strings.Index(mail.Body, "<strong>") + len("<strong>")
	input := ConfirmInput{Binding: requested.Binding, Code: mail.Body[start : start+8], IP: "192.0.2.1"}
	if _, err := s.Confirm(t.Context(), input); !errors.Is(err, domain.ErrInvalidCode) || f.sessionCalls != 0 {
		t.Fatal("native code accepted in browser flow", err)
	}
	verified, err := s.AuthenticateNative(t.Context(), input)
	if err != nil || verified.Proof.Method != "emailotp" || verified.Proof.Reference == "" || verified.Proof.Administrative || verified.Target.Audience != "orders" || f.sessionCalls != 0 {
		t.Fatal("native code lost proof/target or created browser session", err)
	}
	if !slices.Equal(f.keys[4:6], f.keys[6:8]) {
		t.Fatal("confirm budgets not shared between profiles")
	}
}

func TestNativeEmailAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Service, *mfaservice.NativeTarget, *string)
	}{
		{"disabled", func(s *Service, _ *mfaservice.NativeTarget, _ *string) { s.cfg.Enabled = false }},
		{"audience", func(_ *Service, target *mfaservice.NativeTarget, _ *string) { target.Audience = "" }},
		{"scope", func(_ *Service, target *mfaservice.NativeTarget, _ *string) {
			target.Scope = make([]accessdomain.PermissionKey, 65)
		}},
		{"duplicate", func(_ *Service, target *mfaservice.NativeTarget, _ *string) {
			target.Scope = append(target.Scope, target.Scope[0])
		}},
		{"IP zone", func(_ *Service, _ *mfaservice.NativeTarget, ip *string) { *ip = "fe80::1%en0" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, f, _ := otpFixture(t)
			target, ip := mfaservice.NativeTarget{Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}}, "192.0.2.1"
			test.change(s, &target, &ip)
			if _, err := s.RequestNative(t.Context(), "user@example.test", ip, target); err == nil || f.issued != 0 || len(f.keys) != 0 {
				t.Fatal("invalid input reached dependencies", err)
			}
		})
	}
	s, f, _ := otpFixture(t)
	f.allowed = false
	input := ConfirmInput{Binding: strings.Repeat("A", 43), Code: "12345678", IP: "192.0.2.1"}
	if _, err := s.AuthenticateNative(t.Context(), input); !errors.Is(err, domain.ErrLimited) || f.consumed != 0 {
		t.Fatal("rate denial reached SQL", err)
	}
	f.allowed = true
	policyErr := errors.New("policy unavailable")
	s.cfg.CheckPolicy = func(_ context.Context) error { return policyErr }
	if _, err := s.AuthenticateNative(t.Context(), input); !errors.Is(err, policyErr) || f.consumed != 0 {
		t.Fatal("policy failure bypassed", err)
	}
}
