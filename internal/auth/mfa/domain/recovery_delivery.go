package domain

import "errors"

var ErrRecoveryDelivery = errors.New("MFA security notification delivery failed; retry or operator review required")

type RecoveryDelivery struct {
	ID, Lease string
	Payload   []byte
	Attempts  int
	Exhausted bool
}
