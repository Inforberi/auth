package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlatformRecoveryConfirmation(t *testing.T) {
	const realm = "11111111-1111-4111-8111-111111111111"
	const user = "22222222-2222-4222-8222-222222222222"
	opts, err := parseOptions([]string{"-environment", "test", "-user", user, "-reason", "INC-42", "-platform-realm", realm})
	if err != nil || opts.realm != realm {
		t.Fatal("platform password arguments", err)
	}
	destination := recoveryDestination("127.0.0.1:5432", opts.realm)
	if recoveryDestination("127.0.0.1:5432", "") != "127.0.0.1:5432" {
		t.Fatal("legacy confirmation changed")
	}
	reads := 0
	svc := &commandRecovery{}
	var output bytes.Buffer
	if err := execute(t.Context(), opts, destination, svc, strings.NewReader("RESET test 127.0.0.1:5432/auth "+user+" v7\n"), &output, func() ([]byte, error) {
		reads++
		return []byte("Syntheticpassword1"), nil
	}); err == nil || reads != 0 || svc.calls != 0 {
		t.Fatal("confirmation without platform identity accepted")
	}
	if !strings.Contains(output.String(), "[platform="+realm+"]") {
		t.Fatal("platform identity missing from confirmation")
	}
	mfa, err := parseMFAOptions([]string{"mfa-approve", "-environment", "test", "-user", user, "-request", user, "-reason", "INC-42", "-platform-realm", realm})
	if err != nil || mfa.realm != realm {
		t.Fatal("platform MFA arguments", err)
	}
}
