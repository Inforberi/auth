package runtime

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

var (
	ErrUnavailable = errors.New("project runtime unavailable")
	ErrBusy        = errors.New("project runtime capacity exhausted")
	ErrClosed      = errors.New("project runtime registry closed")
)

// Key identifies resources, not authority. A caller must authorize each operation separately.
type Key struct {
	Binding    credentials.Binding
	Version    int64
	Generation int64
}

func (k Key) Valid() bool {
	b := k.Binding
	return domain.ValidID(b.RealmID) && domain.ValidID(b.ProjectID) && domain.ValidID(b.ReservationID) &&
		domain.ValidStorageTarget(b.StorageTarget) && b.DatabaseOID != 0 && b.OwnerOID != 0 &&
		b.RuntimeOID != 0 && b.SchemaVersion > 0 && k.Version > 0 && k.Generation > 0
}

type Config struct {
	MaxRuntimes           int
	ConnectionsPerProject int32
	ConnectionBudget      int
	MaxAcquiring          int
	AcquireTimeout        time.Duration
	OpenTimeout           time.Duration
	IdleTimeout           time.Duration
}

const ReaderMaxConnections int32 = 2

func (c Config) Valid() bool {
	return c.MaxRuntimes > 0 && c.ConnectionsPerProject > 0 &&
		c.ConnectionBudget > 0 && c.MaxRuntimes <= c.ConnectionBudget/int(c.ConnectionsPerProject) &&
		c.MaxAcquiring > 0 && c.AcquireTimeout > 0 && c.OpenTimeout > 0 && c.IdleTimeout > 0
}

type CredentialLoader interface {
	LoadDatabaseCredential(context.Context, Key) (credentials.DatabaseCredential, error)
}

type Database interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type connection interface {
	Database
	Release()
}

type pool interface {
	acquire(context.Context) (connection, error)
	Close()
}

type opener func(context.Context, Key) (pool, error)
