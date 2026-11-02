package sandbox_test

import (
	"encoding/json"
	"testing"

	loadtest "github.com/Inforberi/financial-intelligence/sandbox/internal/loadtest"
)

func TestMixedLoadProfile(t *testing.T) {
	input := loadtest.LoadInputs{Cookie: "synthetic-user", AdminCookie: "synthetic-admin", Basic: "synthetic-service", Token: "synthetic-token"}
	counts := map[string]int{}
	for i := range 20 {
		call := loadtest.MixedLoadCall(i, input)
		counts[call.Name]++
		if call.Name == "introspect" && (call.Cookie != "" || call.Basic != input.Basic || !json.Valid([]byte(call.Body))) {
			t.Fatal("mixed profile crossed service/browser credential boundaries")
		}
	}
	if counts["me"] != 12 || counts["access"] != 5 || counts["roles"] != 2 || counts["introspect"] != 1 {
		t.Fatal("mixed profile weights changed")
	}
}
