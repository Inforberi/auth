package domain

import (
	"errors"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type Purpose string

const (
	Login Purpose = "login"
	Link  Purpose = "link"
)

var (
	ErrDisabled    = errors.New("OIDC login disabled")
	ErrInvalidFlow = errors.New("invalid OIDC login")
	ErrLimited     = errors.New("OIDC login rate limited")
)

type Flow struct {
	ProviderVersion int64                `json:"providerVersion,omitempty"`
	Verifier        string               `json:"verifier"`
	Nonce           string               `json:"nonce"`
	Purpose         Purpose              `json:"purpose"`
	UserID          accountdomain.UserID `json:"userId,omitempty"`
	SessionHash     string               `json:"sessionHash,omitempty"`
}
