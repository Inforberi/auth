package mfahttp

import (
	"context"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type Password interface {
	Authenticate(context.Context, passwordservice.LoginInput) (mfaservice.PrimaryProof, error)
}
