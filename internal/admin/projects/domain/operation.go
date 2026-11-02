package domain

import "errors"

var (
	ErrAdmissionExpired        = errors.New("project operation admission expired")
	ErrOperationOutcomeUnknown = errors.New("project operation outcome unknown")
)
