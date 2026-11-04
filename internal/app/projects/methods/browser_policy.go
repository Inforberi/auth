package methods

import (
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type BrowserPolicy struct {
	Feature string
	Session sessionservice.Config
	MFA     mfaservice.Config
}
