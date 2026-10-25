package postgres

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func (r *RuntimeCredentialReader) LoadSigningKey(ctx context.Context, key projectruntime.Key) (credentials.SigningKey, error) {
	if r == nil {
		return credentials.SigningKey{}, domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	sealed, err := r.readRuntimeCredential(ctx, key)
	if err != nil {
		return credentials.SigningKey{}, err
	}
	defer clear(sealed.payload)
	material, err := r.codec.OpenSigning(key.Binding, sealed.version, sealed.keyID, sealed.payload)
	if err != nil {
		return credentials.SigningKey{}, domain.ErrUnavailable
	}
	current, err := r.CurrentRuntimes(ctx, []projectruntime.Key{key})
	if err != nil || !current[0] {
		material.Clear()
		if err != nil {
			return credentials.SigningKey{}, err
		}
		return credentials.SigningKey{}, domain.ErrConflict
	}
	return material, nil
}
