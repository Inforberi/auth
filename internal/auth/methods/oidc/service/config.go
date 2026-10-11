package service

import "time"

const FlowTTL = 5 * time.Minute

type Config struct {
	Enabled             bool
	RegistrationEnabled bool
	IPLimit             int
	GlobalLimit         int
	Issuer              string
}
