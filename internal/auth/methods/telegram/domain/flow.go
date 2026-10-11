package domain

import "errors"

var (
	ErrDisabled    = errors.New("telegram login disabled")
	ErrInvalidFlow = errors.New("invalid telegram login")
	ErrLimited     = errors.New("telegram login rate limited")
)

type Flow struct {
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce"`
}
