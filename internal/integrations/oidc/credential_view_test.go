package oidcclient

import (
	"net/url"
	"sync"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
)

func TestCredentialViewsReuseTransportAndKeyCache(t *testing.T) {
	owner := New(t.Context(), Config{Issuer: "https://accounts.google.com", AuthorizationURL: "https://accounts.google.com/auth", TokenURL: "https://oauth2.googleapis.com/token", KeysURL: "https://www.googleapis.com/keys", ClientID: "old", ClientSecret: "old-secret"})
	t.Cleanup(owner.Close)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			view := owner.WithCredentials("new-client", "new-secret")
			if view.http != owner.http || view.keys != owner.keys || view.verifier == owner.verifier {
				t.Error("view duplicated resources or audience verifier")
			}
			u, err := url.Parse(view.AuthorizationURL("state", domain.Flow{Verifier: "verifier", Nonce: "nonce"}))
			if err != nil || u.Query().Get("client_id") != "new-client" || view.oauth.ClientSecret != "new-secret" {
				t.Error("view lost credentials")
			}
		})
	}
	wg.Wait()
	if owner.oauth.ClientID != "old" || owner.oauth.ClientSecret != "old-secret" {
		t.Fatal("shared owner mutated")
	}
}
