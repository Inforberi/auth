package model

import (
	"errors"
	"net/mail"
	"strings"
)

var (
	ErrEmailRequired = errors.New("email required")
	ErrEmailInvalid  = errors.New("email invalid")
)

type Email struct {
	value string
}

func NewEmail(raw string) (Email, error) {
	value := normalizeEmail(raw)
	if value == "" {
		return Email{}, ErrEmailRequired
	}
	if len(value) > 255 {
		return Email{}, ErrEmailInvalid
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || address.Name != "" {
		return Email{}, ErrEmailInvalid
	}

	return Email{value: value}, nil
}

func normalizeEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func (e Email) String() string {
	return e.value
}
