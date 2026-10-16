package service

import (
	"context"
	"time"
)

const FlowTTL = 5 * time.Minute

type Config struct {
	CheckPolicy         func(context.Context) error
	Enabled             bool
	RegistrationEnabled bool
	IPLimit             int
	GlobalLimit         int
	Issuer              string
}
