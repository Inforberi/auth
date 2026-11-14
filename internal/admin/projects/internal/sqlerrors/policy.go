package sqlerrors

import (
	"context"
	"errors"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func Policy(ctx context.Context, err error) error {
	if errors.Is(err, settingsdomain.ErrSourceReadOnly) || errors.Is(err, settingsdomain.ErrPolicyConflict) || errors.Is(err, settingsdomain.ErrMethodNotReady) || errors.Is(err, settingsdomain.ErrNotInitialized) {
		return err
	}
	return Catalog(ctx, err)
}
