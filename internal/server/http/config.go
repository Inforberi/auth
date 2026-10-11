package httpserver

import "fmt"

type Config struct {
	Port        string `env:"PORT" env-default:"5000"`
	TLSCertFile string `env:"HTTP_TLS_CERT_FILE"`
	TLSKeyFile  string `env:"HTTP_TLS_KEY_FILE"`
}

func (cfg Config) Validate() error {
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return fmt.Errorf("HTTP_TLS_CERT_FILE and HTTP_TLS_KEY_FILE must be set together")
	}
	return nil
}
