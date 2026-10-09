package mailer

type Config struct {
	RequireTLS   bool   `env:"SMTP_REQUIRE_TLS" env-default:"false"`
	SMTPHost     string `env:"SMTP_HOST" env-required:"true"`
	SMTPPort     string `env:"SMTP_PORT" env-required:"true"`
	SMTPUsername string `env:"SMTP_USERNAME"`
	SMTPPassword string `env:"SMTP_PASSWORD"`
	SMTPFrom     string `env:"SMTP_FROM" env-required:"true"`
	SMTPDomain   string `env:"SMTP_DOMAIN" env-required:"true"`
}
