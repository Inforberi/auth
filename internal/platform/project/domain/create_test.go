package domain

import (
	"strings"
	"testing"
)

func TestCreationPolicyAndCommand(t *testing.T) {
	policy := CreationPolicy{AuthDomain: "auth.example", StorageTarget: "primary", PlatformOrigin: "https://console.auth.example"}
	if !policy.Valid() {
		t.Fatal("valid creation policy rejected")
	}
	for _, base := range []string{"", "https://auth.example", "*.auth.example", "127.0.0.1", "auth.example:8443", "Auth.example", "auth.example/path", "auth.example?query", "auth.example."} {
		bad := policy
		bad.AuthDomain = base
		if bad.Valid() {
			t.Fatal("unsafe base domain", base)
		}
	}
	for _, target := range []string{"", "postgres://host/db", "a;drop", "A", "target name", strings.Repeat("a", 65)} {
		bad := policy
		bad.StorageTarget = target
		if bad.Valid() {
			t.Fatal("unsafe storage target", target)
		}
	}
	input := Create{OperationID: "11111111-1111-4111-8111-111111111111", Slug: "shop", Name: " Shop ", Reason: "incident-123"}
	normalized, err := input.Normalize()
	if err != nil || normalized.Name != "Shop" {
		t.Fatal(err)
	}
	origin, err := policy.Origin(normalized.Slug)
	if err != nil || origin != "https://shop.auth.example" {
		t.Fatal(origin, err)
	}
	for _, mutate := range []func(*Create){
		func(c *Create) { c.OperationID = "invalid" }, func(c *Create) { c.Slug = "api" }, func(c *Create) { c.Slug = "UPPER" },
		func(c *Create) { c.Name = "\nname" }, func(c *Create) { c.Name = " " }, func(c *Create) { c.Reason = "" }, func(c *Create) { c.Reason = " reason " },
	} {
		bad := input
		mutate(&bad)
		if _, err := bad.Normalize(); err == nil {
			t.Fatal("invalid creation accepted")
		}
	}
	policy.PlatformOrigin = "https://shop.auth.example"
	if _, err := policy.Origin("shop"); err == nil {
		t.Fatal("platform host can become a project")
	}
	policy.AuthDomain = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".example"
	if _, err := policy.Origin(strings.Repeat("s", 63)); err == nil {
		t.Fatal("oversized DNS host accepted")
	}
}
