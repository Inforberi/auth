package logger

type Config struct {
	Level string `env:"LOG_LEVEL" env-default:"info"`
	Env   string `env:"APP_ENV" env-default:"dev"`
}
