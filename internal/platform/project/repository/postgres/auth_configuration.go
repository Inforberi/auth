package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

// AuthConfiguration is an assembly snapshot, not permission to serve a request.
type AuthConfiguration struct {
	key        projectruntime.Key
	encryption credentials.AuthKey
	policy     settingsdomain.Snapshot
}

func (c AuthConfiguration) Key() projectruntime.Key         { return c.key }
func (c AuthConfiguration) Policy() settingsdomain.Snapshot { return c.policy }
func (c AuthConfiguration) EncryptionKey() string           { return c.encryption.EncryptionKey() }
func (AuthConfiguration) String() string                    { return "[REDACTED auth configuration]" }
func (c AuthConfiguration) GoString() string                { return c.String() }
func (AuthConfiguration) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED auth configuration]"`), nil
}

func (r *RuntimeCredentialReader) LoadAuthConfiguration(ctx context.Context, key projectruntime.Key, registry *projectruntime.Registry) (AuthConfiguration, error) {
	if r == nil || registry == nil {
		return AuthConfiguration{}, domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	sealed, err := r.readRuntimeCredential(ctx, key)
	if err != nil {
		return AuthConfiguration{}, err
	}
	defer clear(sealed.payload)
	encryption, err := r.codec.OpenAuth(key.Binding, sealed.version, sealed.keyID, sealed.payload)
	if err != nil {
		return AuthConfiguration{}, domain.ErrUnavailable
	}
	var policy settingsdomain.Snapshot
	err = registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
		tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return catalogError(ctx, err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the read result; cleanup cannot write project settings.
		}()
		if err := checkProjectRuntime(ctx, tx, key.Binding); err != nil {
			return err
		}
		policy, err = settingspostgres.ReadPolicyInTransaction(ctx, tx)
		if err != nil {
			if errors.Is(err, settingsdomain.ErrNotInitialized) {
				return err
			}
			return catalogError(ctx, err)
		}
		return catalogError(ctx, tx.Commit(ctx))
	})
	if err != nil {
		return AuthConfiguration{}, err
	}
	current, err := r.CurrentRuntimes(ctx, []projectruntime.Key{key})
	if err != nil {
		return AuthConfiguration{}, err
	}
	if !current[0] {
		return AuthConfiguration{}, domain.ErrConflict
	}
	return AuthConfiguration{key: key, encryption: encryption, policy: policy}, nil
}
