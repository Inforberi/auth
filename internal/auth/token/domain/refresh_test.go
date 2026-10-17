package domain_test

import (
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestRefreshVerifier(t *testing.T) {
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := domain.RefreshVerifier(raw)
	if err != nil || verifier != tokens.Hash(raw) || !domain.ValidRefreshVerifier(verifier) {
		t.Fatal("incompatible opaque generator", err)
	}
	for _, input := range []string{"", raw + "=", " " + raw, raw + " ", "Bearer " + raw, strings.Repeat("x", 42), strings.Repeat("x", 44), strings.Repeat("!", 43), strings.Repeat("A", 42) + "B", "header.payload.signature"} {
		if _, err := domain.RefreshVerifier(input); err == nil {
			t.Fatal("invalid refresh accepted")
		}
	}
	for _, input := range []string{"", strings.Repeat("f", 63), strings.Repeat("F", 64), strings.Repeat("z", 64)} {
		if domain.ValidRefreshVerifier(input) {
			t.Fatal("invalid verifier accepted")
		}
	}
}
