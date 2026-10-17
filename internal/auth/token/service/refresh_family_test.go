package service

import (
	"slices"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
)

func TestRefreshFamilyBinding(t *testing.T) {
	base := CreateRefreshFamilyParams{SessionID: "11111111-1111-4111-8111-111111111111", Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read", "orders.write"}, Verifier: strings.Repeat("a", 64), IdleTTL: time.Hour}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CreateRefreshFamilyParams){
		func(p *CreateRefreshFamilyParams) { p.SessionID = "bad" }, func(p *CreateRefreshFamilyParams) { p.Audience = "bad audience" },
		func(p *CreateRefreshFamilyParams) { p.Scope = nil }, func(p *CreateRefreshFamilyParams) { p.Scope = make([]accessdomain.PermissionKey, 65) },
		func(p *CreateRefreshFamilyParams) { p.Scope[1] = p.Scope[0] }, func(p *CreateRefreshFamilyParams) { p.Scope[0] = "z.read" },
		func(p *CreateRefreshFamilyParams) { p.Scope[0] = "*" }, func(p *CreateRefreshFamilyParams) { p.Verifier = "not a verifier" },
		func(p *CreateRefreshFamilyParams) { p.IdleTTL = 0 }, func(p *CreateRefreshFamilyParams) { p.IdleTTL = time.Second + 1 },
	} {
		candidate := base
		candidate.Scope = slices.Clone(base.Scope)
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
}
