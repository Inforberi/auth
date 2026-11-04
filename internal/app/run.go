package app

import (
	"context"

	accessapp "github.com/Inforberi/financial-intelligence/internal/app/access"
	"github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
)

type App struct {
	Access             *accessapp.App
	Provisioning       *accountprovisioning.ProvisionService
	TemporaryPasswords *passwordprovisioning.TemporaryPasswordService
	serve              func(context.Context) error
	resources          *auth.Resources
}

func (a *App) Run(ctx context.Context) error {
	defer a.Close()
	return a.serve(ctx)
}

// Close is idempotent. Normally Run closes the application; callers that do not
// start it must call Close themselves. Do not close it while Run is active.
func (a *App) Close() {
	a.resources.Close()
}
