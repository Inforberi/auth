package postgres

import "time"

type Config struct {
	URL             string        `env:"DATABASE_URL" env-required:"true"`
	MaxConns        int32         `env:"MAX_CONNS" env-default:"10"`
	MinConns        int32         `env:"MIN_CONNS" env-default:"2"`
	MaxConnLifetime time.Duration `env:"MAX_CONN_LIFETIME" env-default:"10m"`
	MaxConnIdleTime time.Duration `env:"MAX_CONN_IDLE_TIME" env-default:"5m"`
}
