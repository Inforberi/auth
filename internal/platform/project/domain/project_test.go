package domain

import (
	"strings"
	"testing"
)

func TestProjectIdentity(t *testing.T) {
	if !ValidID("1c82c477-3a57-4823-8c49-a476550d8a21") {
		t.Fatal("valid project ID rejected")
	}
	for _, id := range []ID{"", "00000000-0000-0000-0000-000000000000", "1C82C477-3a57-4823-8c49-a476550d8a21", "not-a-uuid"} {
		if ValidID(id) {
			t.Fatalf("invalid project ID accepted: %q", id)
		}
	}
	for _, slug := range []string{"a", "shop-2", strings.Repeat("a", 63)} {
		if !ValidSlug(slug) {
			t.Fatalf("valid slug rejected: %q", slug)
		}
	}
	for _, slug := range []string{"", "admin", "api", "auth", "console", "platform", "www", "Shop", "-shop", "shop-", "shop.x", "магазин", strings.Repeat("a", 64)} {
		if ValidSlug(slug) {
			t.Fatalf("invalid/reserved slug accepted: %q", slug)
		}
	}
	name, err := NormalizeName("  Магазин  ")
	if err != nil || name != "Магазин" {
		t.Fatal("display name was not normalized")
	}
	for _, name := range []string{"", "  ", "shop\n", "shop\x00", "shop\u0085", string([]byte{0xff}), strings.Repeat("я", 101)} {
		if _, err := NormalizeName(name); err == nil {
			t.Fatal("invalid display name accepted")
		}
	}
}

func TestCanonicalProjectOrigins(t *testing.T) {
	for _, origin := range []string{"https://shop.auth.example", "https://shop.localhost:18443"} {
		if !ValidOrigin(origin) {
			t.Fatalf("valid origin rejected: %q", origin)
		}
	}
	for _, origin := range []string{
		"", "http://shop.auth.example", "https://Shop.auth.example", "https://shop.auth.example/",
		"https://shop.auth.example?", "https://shop.auth.example#fragment", "https://user@shop.auth.example",
		"https://shop.auth.example:443", "https://shop.auth.example:", "https://shop.auth.example:06543",
		"https://shop.auth.example:65536", "https://127.0.0.1", "https://[::1]", "https://shop..example",
		"https://shop.example.", "https://-shop.example", "https://shop.example/path", "https://shop.example\\evil",
	} {
		if ValidOrigin(origin) {
			t.Fatalf("noncanonical origin accepted: %q", origin)
		}
	}
}

func TestProjectAdmissionIsFailClosed(t *testing.T) {
	for _, state := range []DesiredState{Enabled, Suspended, "", "unknown"} {
		for _, phase := range []Phase{Pending, Provisioning, Failed, Ready, "", "unknown"} {
			project := Project{DesiredState: state, Phase: phase}
			if project.AdmitsRequests() != (state == Enabled && phase == Ready) {
				t.Fatal("unexpected catalog admission")
			}
		}
	}
}
