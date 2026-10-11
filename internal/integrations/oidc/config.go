package oidcclient

import "golang.org/x/oauth2"

type Config struct {
	Issuer           string
	AuthorizationURL string
	TokenURL         string
	KeysURL          string
	ClientID         string
	ClientSecret     string
	RedirectURI      string
	AuthStyle        oauth2.AuthStyle
}
