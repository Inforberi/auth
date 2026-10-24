package runtime

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type ProfileCheck func(context.Context, *pgx.Conn, credentials.Binding) error

type projectPool struct{ *pgxpool.Pool }

func (p projectPool) acquire(ctx context.Context) (connection, error) { return p.Acquire(ctx) }

func New(cfg Config, targets map[string]Target, loader CredentialLoader, check ProfileCheck) (*Registry, error) {
	if !cfg.valid() || len(targets) == 0 || loader == nil || check == nil {
		return nil, ErrUnavailable
	}
	trusted := make(map[string]Target, len(targets))
	for name, target := range targets {
		if !domain.ValidStorageTarget(name) || target.host == "" {
			return nil, ErrUnavailable
		}
		trusted[name] = target
	}
	return newRegistry(cfg, func(ctx context.Context, key Key) (pool, error) {
		target, found := trusted[key.Binding.StorageTarget]
		if !found {
			return nil, ErrUnavailable
		}
		value, err := loader.LoadDatabaseCredential(ctx, key)
		if err != nil || value.Binding() != key.Binding || value.Password() == "" {
			return nil, ErrUnavailable
		}
		config, err := poolConfig(cfg, target, value)
		if err != nil {
			return nil, ErrUnavailable
		}
		// Every new physical connection is checked, not just one successful Ping.
		config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			return check(ctx, conn, key.Binding)
		}
		p, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			return nil, ErrUnavailable
		}
		if err := p.Ping(ctx); err != nil {
			p.Close()
			return nil, ErrUnavailable
		}
		return projectPool{p}, nil
	}), nil
}

func poolConfig(cfg Config, target Target, value credentials.DatabaseCredential) (*pgxpool.Config, error) {
	// Explicit bootstrap values; no project endpoint or password is parsed as a URL.
	p, err := pgxpool.ParseConfig("postgres://runtime@localhost:5432/runtime?sslmode=disable&connect_timeout=1")
	if err != nil {
		return nil, ErrUnavailable
	}
	b := value.Binding()
	database, owner, err := (domain.PreparationReservation{ProjectID: b.ProjectID, ReservationID: b.ReservationID}).ResourceNames()
	if err != nil {
		return nil, ErrUnavailable
	}
	c := p.ConnConfig
	c.Host, c.Port, c.Database = target.host, target.port, database
	c.User, c.Password = "authr_"+strings.TrimPrefix(owner, "autho_"), value.Password()
	c.TLSConfig, c.Fallbacks = nil, nil
	if target.tls != nil {
		c.TLSConfig = target.tls.Clone()
	}
	c.ConnectTimeout = cfg.OpenTimeout
	c.DialFunc = (&net.Dialer{Timeout: cfg.OpenTimeout}).DialContext
	c.LookupFunc = net.DefaultResolver.LookupHost
	c.KerberosSrvName, c.KerberosSpn, c.SSLNegotiation = "", "", "postgres"
	c.OAuthTokenProvider = nil
	c.ValidateConnect, c.AfterConnect = nil, nil
	c.MinProtocolVersion, c.MaxProtocolVersion = "3.0", "3.0"
	c.RequireAuth, c.ChannelBinding = "scram-sha-256", "prefer"
	c.RuntimeParams = map[string]string{
		"application_name": "auth-project-runtime", "statement_timeout": "3000",
		"lock_timeout": "1000", "idle_in_transaction_session_timeout": "3000", "transaction_timeout": "3000",
	}
	p.MaxConns, p.MinConns, p.MinIdleConns = cfg.ConnectionsPerProject, 0, 0
	p.MaxConnLifetimeJitter, p.PingTimeout = time.Minute, time.Second
	p.MaxConnIdleTime, p.MaxConnLifetime, p.HealthCheckPeriod = cfg.IdleTimeout, time.Hour, min(cfg.IdleTimeout, time.Minute)
	return p, nil
}
