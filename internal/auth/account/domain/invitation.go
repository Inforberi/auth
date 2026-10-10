package domain

import "errors"

var (
	ErrInvalidInvitation    = errors.New("invalid invitation")
	ErrProvisionConflict    = errors.New("provisioning request conflict")
	ErrProvisionEmailExists = errors.New("provisioning email already exists")
	ErrProvisionDisabled    = errors.New("provisioning disabled")
)

type Invitation struct {
	Digest  string
	Payload []byte
}
