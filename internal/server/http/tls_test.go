package httpserver

import (
	"context"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestTLSConfigurationAndStartupFailure(t *testing.T) {
	for _, cfg := range []Config{{}, {TLSCertFile: "cert", TLSKeyFile: "key"}} {
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, cfg := range []Config{{TLSCertFile: "cert"}, {TLSKeyFile: "key"}} {
		if cfg.Validate() == nil {
			t.Fatal("partial TLS config accepted")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	err := Run(ctx, zap.NewNop(), Config{Port: "0", TLSCertFile: t.TempDir() + "/missing.pem", TLSKeyFile: "missing.key"}, http.NotFoundHandler())
	if err == nil {
		t.Fatal("TLS failure silently fell back to plaintext")
	}
}
