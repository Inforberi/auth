package service_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	providers "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
)

func TestProviderReplacementLockedCredentials(t *testing.T) {
	before := providers.ProviderStored{ProviderSnapshot: domain.ProviderSnapshot{ClientID: "old", SecretSet: true}, Secret: []byte("old encrypted secret")}
	for _, tc := range []struct {
		name, client string
		secret       []byte
		set, enabled bool
		want         []byte
		wantSet      bool
		err          error
	}{
		{name: "preserve enabled", client: "old", enabled: true, want: before.Secret, wantSet: true},
		{name: "preserve disabled", client: "old", want: before.Secret, wantSet: true},
		{name: "client change without secret", client: "new", enabled: true, err: domain.ErrInvalidProvider},
		{name: "rotate enabled", client: "old", secret: []byte("new encrypted secret"), set: true, enabled: true, want: []byte("new encrypted secret"), wantSet: true},
		{name: "enabled client change", client: "new", secret: []byte("new encrypted secret"), set: true, enabled: true, err: domain.ErrMethodNotReady},
		{name: "disabled client change", client: "new", secret: []byte("new encrypted secret"), set: true, want: []byte("new encrypted secret"), wantSet: true},
		{name: "enabled clear", client: "old", secret: []byte("encrypted empty"), enabled: true, err: domain.ErrMethodNotReady},
		{name: "disabled clear", client: "old", secret: []byte("encrypted empty"), want: []byte("encrypted empty")},
		{name: "secret without client", secret: []byte("new encrypted secret"), set: true, err: domain.ErrInvalidProvider},
		{name: "readiness before client error", secret: []byte("new encrypted secret"), set: true, enabled: true, err: domain.ErrMethodNotReady},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := providers.ProviderUpdate{ClientID: tc.client, Secret: tc.secret, SecretSet: tc.set}
			secret, set, err := input.Replacement(before, tc.enabled)
			if !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
			if err == nil && (!bytes.Equal(secret, tc.want) || set != tc.wantSet) {
				t.Fatal("incorrect credential preservation/replacement")
			}
			if string(before.Secret) != "old encrypted secret" || !before.SecretSet || before.ClientID != "old" {
				t.Fatal("stored snapshot mutated")
			}
		})
	}
}
