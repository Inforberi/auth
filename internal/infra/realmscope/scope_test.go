package realmscope

import (
	"strings"
	"testing"
)

func TestExplicitScope(t *testing.T) {
	for _, input := range []struct{ kind, id string }{
		{"", ""},
		{"project", ""},
		{"other", "1c82c477-3a57-4823-8c49-a476550d8a21"},
		{"project", "00000000-0000-0000-0000-000000000000"},
		{"platform", "1C82c477-3a57-4823-8c49-a476550d8a21"},
		{"project", "1c82c477-3a57-4823-8c49-a476550d8a2z"},
		{"project", "1c82c477{3a57-4823-8c49-a476550d8a21"},
	} {
		if _, err := New(input.kind, input.id); err == nil {
			t.Fatalf("invalid scope accepted: %+v", input)
		}
	}
	if (Scope{}).Valid() {
		t.Fatal("zero scope silently became legacy")
	}
	if _, err := (Scope{}).RedisPrefix("mfa-limit", "auth:mfa:limit:"); err == nil {
		t.Fatal("zero scope accepted Redis operations")
	}
	if _, err := (Scope{}).Purpose("mfa:v1"); err == nil {
		t.Fatal("zero scope accepted encryption")
	}
}

func TestPurposeAndHashTagIsolation(t *testing.T) {
	id := "1c82c477-3a57-4823-8c49-a476550d8a21"
	platform, err := New("platform", id)
	if err != nil {
		t.Fatal(err)
	}
	project, err := New("project", id)
	if err != nil {
		t.Fatal(err)
	}
	other, err := New("project", "2c82c477-3a57-4823-8c49-a476550d8a21")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, scope := range []Scope{platform, project, other} {
		for _, purpose := range []string{"mfa-limit", "jwt-issuance", "jwt-introspection"} {
			prefix, err := scope.RedisPrefix(purpose, "legacy")
			if err != nil {
				t.Fatal(err)
			}
			_, after, _ := strings.Cut(prefix, "{")
			tag, _, _ := strings.Cut(after, "}")
			if !strings.HasPrefix(tag, "realm:") || !strings.HasSuffix(tag, ":"+purpose) || seen[tag] {
				t.Fatalf("missing/shared realm-purpose hash tag %q", tag)
			}
			seen[tag] = true
		}
	}
	for _, purpose := range []string{"", "mfa{evil}", "mfa\n", "mfa/../../", strings.Repeat("a", 97)} {
		if _, err := project.Purpose(purpose); err == nil {
			t.Fatal("unbounded/unsafe purpose accepted")
		}
	}
}

func TestLegacyCompatibility(t *testing.T) {
	legacy := Legacy()
	for _, purpose := range []string{"email-verification:v1", "mfa:v1", "smtp-settings:v1"} {
		if got, err := legacy.Purpose(purpose); err != nil || got != purpose {
			t.Fatal("legacy encryption purpose changed", got, err)
		}
	}
	for _, prefix := range []string{"auth:mfa:limit:", "auth:{jwt-issuance}:", "auth:google"} {
		if got, err := legacy.RedisPrefix("fixture", prefix); err != nil || got != prefix {
			t.Fatal("legacy Redis key changed", got, err)
		}
	}
}
