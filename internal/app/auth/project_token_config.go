package auth

import (
	"time"

	"github.com/redis/go-redis/v9"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type ProjectNativeConfig struct {
	PasswordEnabled    bool
	Capacity           passwordservice.CapacityConfig
	EmailOTP           otpservice.Config
	MFA                mfaservice.Config
	SMTPAllowedTargets []string
}

type ProjectIntrospectionConfig struct {
	Clients                             []tokenservice.IntrospectionClientConfig
	ConsumerPerMinute, ProjectPerMinute int
}

type ProjectTokenConfig struct {
	Introspection *ProjectIntrospectionConfig
	Enabled       bool
	Issuer        string
	Tokens        tokenservice.Config
	Catalog       accesssettings.Catalog
	Limits        tokenredis.Limits
	Native        ProjectNativeConfig
	Timeout       time.Duration
}

type ProjectTokenDependencies struct {
	Registry      *projectruntime.Registry
	Reader        *runtimepostgres.RuntimeCredentialReader
	Redis         *redis.Client
	IssuanceRedis *redis.Client
	Hash          *hasher.Bounded
}

func (c ProjectTokenConfig) validate(deps ProjectTokenDependencies) error {
	if !c.Enabled {
		return nil
	}
	if deps.Registry == nil || deps.Reader == nil || deps.IssuanceRedis == nil || c.Timeout <= 0 || c.Timeout > 30*time.Second {
		return authjwt.ErrConfiguration
	}
	if !validProjectTokenRedis(deps.IssuanceRedis) {
		return authjwt.ErrConfiguration
	}
	if err := authjwt.ValidateIssuer(c.Issuer); err != nil {
		return err
	}
	if c.Tokens.Native == nil {
		if c.Native.PasswordEnabled || c.Native.EmailOTP.Enabled {
			return authjwt.ErrConfiguration
		}
		return nil
	}
	if deps.Redis == nil || !c.Native.MFA.Enabled {
		return authjwt.ErrConfiguration
	}
	if err := c.Tokens.Native.Sessions.Validate(); err != nil {
		return err
	}
	if err := validateProjectMFA(c.Native.MFA); err != nil {
		return err
	}
	if c.Native.PasswordEnabled {
		if deps.Hash == nil {
			return authjwt.ErrConfiguration
		}
		if err := c.Native.Capacity.Validate(); err != nil {
			return err
		}
	}
	return c.Native.EmailOTP.Validate()
}
