package domain

import "errors"

var ErrSecurityDelivery = errors.New("MFA security notification delivery failed; retry or operator review required")

type SecurityDelivery struct {
	ID, Lease string
	Payload   []byte
	Attempts  int
	Exhausted bool
}
