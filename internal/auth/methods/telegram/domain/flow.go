package domain

import (
	"errors"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

const Issuer = "https://oauth.telegram.org"

type Purpose string

const (
	Login Purpose = "login"
	Link  Purpose = "link"
)

var (
	ErrDisabled    = errors.New("telegram login disabled")
	ErrInvalidFlow = errors.New("invalid telegram login")
	ErrLimited     = errors.New("telegram login rate limited")
)

type Flow struct {
	Verifier    string               `json:"verifier"`
	Nonce       string               `json:"nonce"`
	Purpose     Purpose              `json:"purpose"`
	UserID      accountdomain.UserID `json:"userId,omitempty"`
	SessionHash string               `json:"sessionHash,omitempty"`
}
