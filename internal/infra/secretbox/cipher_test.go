package secretbox

import (
	"bytes"
	"testing"
)

func TestCipher(t *testing.T) {
	c, err := New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("secret verification link")
	a, err := c.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) || bytes.Contains(a, plain) {
		t.Fatal("payload is deterministic or contains plaintext")
	}
	restored, err := c.Open(a)
	if err != nil || !bytes.Equal(restored, plain) {
		t.Fatal("round trip failed")
	}
	a[len(a)-1] ^= 1
	if _, err := c.Open(a); err == nil {
		t.Fatal("tampered payload accepted")
	}
	if _, err := c.Open([]byte("short")); err == nil {
		t.Fatal("truncated payload accepted")
	}
	if c.Digest("ip:127.0.0.1") == c.Digest("email:127.0.0.1") {
		t.Fatal("limit namespaces overlap")
	}
	if _, err := New("bad"); err == nil {
		t.Fatal("invalid key accepted")
	}
}
