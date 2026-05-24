package httpserver

type Config struct {
	Port string `env:"PORT" env-default:"5000"`
}
