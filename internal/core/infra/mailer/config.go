package mailer

type Config struct {
	SMTPHost     string `env:"SMTP_HOST" env-required:"true"`
	SMTPPort     string `env:"SMTP_PORT" env-required:"true"`
	SMTPUsername string `env:"SMTP_USERNAME" env-required:"true"`
	SMTPPassword string `env:"SMTP_PASSWORD" env-required:"true"`
	SMTPFrom     string `env:"SMTP_FROM" env-required:"true"`
}
