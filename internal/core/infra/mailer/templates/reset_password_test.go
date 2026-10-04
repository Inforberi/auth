package templates

import (
	"strings"
	"testing"
	"time"
)

func TestRenderResetPassword(t *testing.T) {
	body, err := RenderResetPassword("https://example.com/reset?locale=ru", "a&b", time.Hour, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"token=a%26b", "locale=ru", "1h0m0s", "2026"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q", want)
		}
	}
	for _, bad := range []string{"javascript:alert(1)", "https://user:password@example.com/reset", "/reset", "https://example.com/reset#fragment"} {
		if _, err := RenderResetPassword(bad, "token", time.Hour, time.Now()); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
