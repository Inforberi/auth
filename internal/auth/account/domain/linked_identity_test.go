package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestIdentityKeyValidation(t *testing.T) {
	for _, key := range []IdentityKey{
		{},
		{Issuer: "issuer"},
		{Subject: "subject"},
		{Issuer: " ", Subject: "subject"},
		{Issuer: "issuer", Subject: "\n"},
		{Issuer: strings.Repeat("i", 513), Subject: "s"},
		{Issuer: "i", Subject: strings.Repeat("s", 256)},
		{Issuer: "i", Subject: "s\x00"},
		{Issuer: "i\xff", Subject: "s"},
	} {
		if err := key.Validate(); !errors.Is(err, ErrInvalidIdentity) {
			t.Fatal("invalid key accepted", err)
		}
	}
	key := IdentityKey{Issuer: strings.Repeat("i", 512), Subject: strings.Repeat("s", 255)}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	key = IdentityKey{Issuer: "https://Provider.example/", Subject: "Subject-Case"}
	if err := key.Validate(); err != nil || key.Issuer != "https://Provider.example/" || key.Subject != "Subject-Case" {
		t.Fatal("opaque key modified", err)
	}
}
