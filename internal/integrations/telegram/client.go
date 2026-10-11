package telegram

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/service"
)

const Issuer = domain.Issuer

type Client struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	http     *boundedTransport
	cancel   context.CancelFunc
}

func New(ctx context.Context, cfg service.Config) *Client {
	transport, httpClient := newHTTPClient()
	lifetime, cancel := context.WithCancel(ctx)
	ctx = oidc.ClientContext(lifetime, httpClient)
	return &Client{
		oauth: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURI,
			Scopes: []string{oidc.ScopeOpenID}, Endpoint: oauth2.Endpoint{
				AuthURL: Issuer + "/auth", TokenURL: Issuer + "/token", AuthStyle: oauth2.AuthStyleInHeader,
			},
		},
		verifier: oidc.NewVerifier(Issuer, oidc.NewRemoteKeySet(ctx, Issuer+"/.well-known/jwks.json"),
			&oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: []string{oidc.RS256}}),
		http:   transport,
		cancel: cancel,
	}
}

func (c *Client) Close() { c.cancel(); c.http.transport.CloseIdleConnections() }

func (c *Client) AuthorizationURL(state string, flow domain.Flow) string {
	return c.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(flow.Verifier), oidc.Nonce(flow.Nonce))
}

func (c *Client) Verify(ctx context.Context, code string, flow domain.Flow) (accountdomain.IdentityKey, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.http.client)
	token, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(flow.Verifier), oauth2.SetAuthURLParam("client_id", c.oauth.ClientID))
	if err != nil {
		var response *oauth2.RetrieveError
		if errors.As(err, &response) && response.ErrorCode == "invalid_grant" {
			return accountdomain.IdentityKey{}, domain.ErrInvalidFlow
		}
		return accountdomain.IdentityKey{}, errors.New("telegram token exchange unavailable")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 16384 || flow.Nonce == "" {
		return accountdomain.IdentityKey{}, domain.ErrInvalidFlow
	}
	verified, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return accountdomain.IdentityKey{}, domain.ErrInvalidFlow
	}
	if subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(flow.Nonce)) != 1 {
		return accountdomain.IdentityKey{}, domain.ErrInvalidFlow
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if err := verified.Claims(&claims); err != nil ||
		(len(verified.Audience) > 1 && claims.AuthorizedParty != c.oauth.ClientID) ||
		(claims.AuthorizedParty != "" && claims.AuthorizedParty != c.oauth.ClientID) ||
		verified.IssuedAt.IsZero() || verified.IssuedAt.After(time.Now().Add(time.Minute)) || !time.Now().Before(verified.Expiry) {
		return accountdomain.IdentityKey{}, domain.ErrInvalidFlow
	}
	return accountdomain.IdentityKey{Issuer: verified.Issuer, Subject: verified.Subject}, nil
}
