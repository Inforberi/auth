package authjwt

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPublicKeys(t *testing.T) {
	key, raw := testKey(t, "current")
	keys, err := ParsePublicKeys(raw)
	point, encodeErr := key.PublicKey.Bytes()
	if err != nil || encodeErr != nil || !keys.Matches("current", point) {
		t.Fatal(err)
	}
	copy1 := keys.JWKS()
	copy1[0] = 'x'
	if keys.JWKS()[0] != '{' {
		t.Fatal("caller mutated public response")
	}
	raw[0] = 'x'
	if keys.JWKS()[0] != '{' {
		t.Fatal("caller mutated source snapshot")
	}
	if keys.Matches("current", make([]byte, 65)) {
		t.Fatal("invalid public point matched")
	}
	_, valid := testKey(t, "current")
	var set map[string][]map[string]any
	if err := json.Unmarshal(valid, &set); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"private":      func(k map[string]any) { k["d"] = "secret" },
		"embedded URL": func(k map[string]any) { k["x5u"] = "https://evil.test" },
		"wrong curve":  func(k map[string]any) { k["crv"] = "P-384" },
		"wrong type":   func(k map[string]any) { k["kty"] = "RSA" },
		"wrong alg":    func(k map[string]any) { k["alg"] = "HS256" },
		"wrong use":    func(k map[string]any) { k["use"] = "enc" },
		"wrong ops":    func(k map[string]any) { k["key_ops"] = []string{"sign", "verify"} },
		"empty ops":    func(k map[string]any) { k["key_ops"] = []string{} },
		"null ops":     func(k map[string]any) { k["key_ops"] = nil },
		"coordinate":   func(k map[string]any) { k["x"] = "AAAA" },
		"point":        func(k map[string]any) { k["x"] = strings.Repeat("A", 43); k["y"] = strings.Repeat("A", 43) },
		"kid path":     func(k map[string]any) { k["kid"] = "../current" },
	} {
		t.Run(name, func(t *testing.T) {
			var copySet map[string][]map[string]any
			_ = json.Unmarshal(valid, &copySet)
			mutate(copySet["keys"][0])
			data, _ := json.Marshal(copySet)
			if _, err := ParsePublicKeys(data); !errors.Is(err, ErrConfiguration) {
				t.Fatal("accepted invalid key", err)
			}
		})
	}
	for _, data := range []string{`null`, `{}`, `{"keys":[]}`, string(valid[:len(valid)-1]) + `,"url":"evil"}`, strings.Replace(string(valid), `"keys":`, `"keys":[],"keys":`, 1), strings.Repeat(" ", MaxJWKSBytes+1)} {
		if _, err := ParsePublicKeys([]byte(data)); !errors.Is(err, ErrConfiguration) {
			t.Fatal("accepted invalid set", err)
		}
	}
	data, _ := json.Marshal(map[string]any{"keys": []map[string]any{set["keys"][0], set["keys"][0]}})
	if _, err := ParsePublicKeys(data); err == nil {
		t.Fatal("duplicate kid")
	}
	if _, err := ParsePublicKeys([]byte(strings.Replace(string(valid), `"kid":"current"`, `"kid":"current","kid":"other"`, 1))); err == nil {
		t.Fatal("duplicate key member")
	}
	for range 5 {
		set["keys"] = append(set["keys"], set["keys"][0])
	}
	tooMany, _ := json.Marshal(set)
	if _, err := ParsePublicKeys(tooMany); err == nil {
		t.Fatal("too many keys")
	}
	set["keys"] = set["keys"][:1]
	set["keys"][0]["key_ops"] = []string{"verify"}
	data, _ = json.Marshal(set)
	if _, err := ParsePublicKeys(data); err != nil {
		t.Fatal("valid key ops", err)
	}
}

func TestPublicRotation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old, rawOld := testKey(t, "current")
	newKey, rawNew := testKey(t, "next")
	var oldSet, newSet struct {
		Keys []json.RawMessage `json:"keys"`
	}
	_ = json.Unmarshal(rawOld, &oldSet)
	_ = json.Unmarshal(rawNew, &newSet)
	oldSet.Keys = append(oldSet.Keys, newSet.Keys...)
	overlap, _ := json.Marshal(oldSet)
	data, _ := json.Marshal(testClaims(now))
	oldToken := signPayload(t, old, "current", data)
	newToken := signPayload(t, newKey, "next", data)
	for _, token := range []string{oldToken, newToken} {
		if _, err := fixtureVerifier(t, overlap, now).VerifySignature(t.Context(), token, now); err != nil {
			t.Fatal("overlap rejected", err)
		}
	}
	if _, err := fixtureVerifier(t, rawOld, now).VerifySignature(t.Context(), newToken, now); err == nil {
		t.Fatal("unpublished key trusted")
	}
	retired := fixtureVerifier(t, rawNew, now)
	if _, err := retired.VerifySignature(t.Context(), oldToken, now); err == nil {
		t.Fatal("retired key trusted")
	}
	if _, err := retired.VerifySignature(t.Context(), newToken, now); err != nil {
		t.Fatal(err)
	}
	keys, _ := ParsePublicKeys(rawNew)
	owner := fixtureVerifier(t, overlap, now)
	if err := owner.ReplaceKeys(keys, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.VerifySignature(t.Context(), oldToken, now.Add(time.Second)); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("retired key survived replacement", err)
	}
	if _, err := owner.VerifySignature(t.Context(), newToken, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := owner.ReplaceKeys(keys, now); !errors.Is(err, ErrConfiguration) {
		t.Fatal("out-of-order trust rollback accepted", err)
	}
}

func TestVerifierConfiguration(t *testing.T) {
	_, raw := testKey(t, "current")
	keys, _ := ParsePublicKeys(raw)
	for _, e := range []Expectations{{}, {Issuer: "http://auth.example", Audience: "orders", Mode: Strict}, {Issuer: "https://u:p@auth.example", Audience: "orders", Mode: Strict}, {Issuer: "https://auth.example?q=1", Audience: "orders", Mode: Strict}, {Issuer: "https://auth.example", Audience: " ", Mode: Strict}, {Issuer: "https://auth.example", Audience: "orders", Mode: "auto"}} {
		if _, err := NewVerifier(e, keys, time.Now()); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid expectations", e, err)
		}
	}
	valid := Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: Strict}
	if _, err := NewVerifier(valid, nil, time.Now()); err == nil {
		t.Fatal("missing keys")
	}
	if _, err := NewVerifier(valid, keys, time.Time{}); err == nil {
		t.Fatal("missing trust timestamp")
	}
}

func FuzzPublicKeys(f *testing.F) {
	_, valid := testKey(f, "current")
	f.Add(valid)
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := ParsePublicKeys(data)
		if err == nil {
			if len(keys.keys) < 1 || len(keys.keys) > 4 {
				t.Fatal("unbounded set")
			}
			if _, err := ParsePublicKeys(keys.JWKS()); err != nil {
				t.Fatal("public snapshot not reproducible", err)
			}
		}
	})
}
