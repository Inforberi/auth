package service

import (
	mfadelivery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/delivery/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type FactorMutation struct {
	mfaservice.Proof
	PrepareNotice mfadelivery.PrepareSecurityNotice
}
