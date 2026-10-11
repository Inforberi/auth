package hasher

import (
	"errors"
	"strings"
	"testing"
)

func TestStrictEncodedHash(t *testing.T) {
	old := NewArgon2idHash(1, 16, 1024, 1, 32)
	encoded, err := old.GenerateHash([]byte("Password123"))
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Compare("Password123", encoded); err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		"prefix" + encoded,
		strings.Replace(encoded, "p=1$", "p=1trailing$", 1),
		strings.Replace(encoded, "m=1024", "m=+1024", 1),
		strings.Replace(encoded, "m=1024", "m=4294967296", 1),
		strings.Replace(encoded, "p=1", "p=0", 1),
		strings.Replace(encoded, "v=19", "v=16", 1),
		encoded + "\n", encoded + "$", strings.Repeat("x", 4097),
	} {
		if err := old.Compare("Password123", malformed); !errors.Is(err, ErrInvalidHashFormat) {
			t.Fatalf("accepted malformed hash: %v", err)
		}
	}
	target := NewArgon2idHash(2, 16, 1024, 1, 32)
	if !target.NeedsRehash(encoded) || old.NeedsRehash(encoded) {
		t.Fatal("wrong upgrade decision")
	}
	strong, err := NewArgon2idHash(3, 16, 2048, 1, 32).GenerateHash([]byte("Password123"))
	if err != nil {
		t.Fatal(err)
	}
	if target.NeedsRehash(strong) {
		t.Fatal("cost downgrade")
	}
}

func TestLegacyProductionHash(t *testing.T) {
	legacy := NewArgon2idHash(1, 32, 64*1024, 32, 256)
	encoded, err := legacy.GenerateHash([]byte("existing-password"))
	if err != nil {
		t.Fatal(err)
	}
	target := NewArgon2idHash(3, 32, 64*1024, 4, 32)
	if err := target.Compare("existing-password", encoded); err != nil {
		t.Fatal(err)
	}
	if !target.NeedsRehash(encoded) {
		t.Fatal("old production profile not upgraded")
	}
	replacement, err := target.GenerateHash([]byte("existing-password"))
	if err != nil {
		t.Fatal(err)
	}
	if target.NeedsRehash(replacement) {
		t.Fatal("endless rehash")
	}
	if err := target.Compare("existing-password", replacement); err != nil {
		t.Fatal(err)
	}
}

func FuzzEncodedHash(f *testing.F) {
	f.Add("$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("$argon2id$v=19$m=999999999999,t=1,p=32$x$y")
	f.Fuzz(func(t *testing.T, encoded string) {
		p, err := parse(encoded)
		if err == nil && (p.memory > 256*1024 || p.time > 10 || p.threads > 32 || len(p.key) > 256 || len(p.salt) > 64) {
			t.Fatal("unbounded parser")
		}
	})
}
