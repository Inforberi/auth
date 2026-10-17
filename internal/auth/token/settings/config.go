package settings

import (
	"time"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type Config struct {
	Enabled          bool          `env:"JWT_ENABLED" env-default:"false"`
	Issuer           string        `env:"JWT_ISSUER"`
	SigningKeyID     string        `env:"JWT_SIGNING_KEY_ID"`
	PrivateKeyFile   string        `env:"JWT_PRIVATE_KEY_FILE"`
	KeySetFile       string        `env:"JWT_KEYSET_FILE"`
	ResourceFile     string        `env:"JWT_RESOURCE_CONFIG_FILE"`
	AccessTTL        time.Duration `env:"JWT_ACCESS_TTL" env-default:"2m"`
	ActorPerMinute   int           `env:"JWT_ISSUANCE_ACTOR_LIMIT_PER_MINUTE" env-default:"30"`
	SessionPerMinute int           `env:"JWT_ISSUANCE_SESSION_LIMIT_PER_MINUTE" env-default:"10"`
	IPPerMinute      int           `env:"JWT_ISSUANCE_IP_LIMIT_PER_MINUTE" env-default:"30"`
	ProjectPerMinute int           `env:"JWT_ISSUANCE_PROJECT_LIMIT_PER_MINUTE" env-default:"3000"`
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if authjwt.ValidateIssuer(c.Issuer) != nil || !authjwt.ValidKeyID(c.SigningKeyID) || c.PrivateKeyFile == "" || c.KeySetFile == "" || c.ResourceFile == "" ||
		c.AccessTTL < time.Second || c.AccessTTL > authjwt.MaxLifetime || c.AccessTTL%time.Second != 0 {
		return authjwt.ErrConfiguration
	}
	for _, limit := range []int{c.ActorPerMinute, c.SessionPerMinute, c.IPPerMinute, c.ProjectPerMinute} {
		if limit < 1 || limit > 1_000_000 {
			return authjwt.ErrConfiguration
		}
	}
	return nil
}
