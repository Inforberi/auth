package hasher

import (
	"errors"
	"testing"
)

func TestHashCompatibilityAndBounds(t *testing.T) {
	a := NewArgon2idHash(1, 16, 64*1024, 1, 32)
	hash, err := a.GenerateHash([]byte("Password123"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Compare("Password123", hash); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(a.Compare("wrong", hash), ErrPasswordMismatch) {
		t.Fatal("wrong password accepted")
	}
	for _, hash := range []string{
		"$argon2id$v=19$m=65536,t=1,p=0$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=999999999999999,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=0,p=1$c2FsdA$aGFzaA",
	} {
		if !errors.Is(a.Compare("x", hash), ErrInvalidHashFormat) {
			t.Fatal("unsafe hash accepted")
		}
	}
}
