package authjwt_test

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func ExampleConsumer_Middleware() {
	consumer, err := authjwt.NewConsumer(context.Background(), authjwt.ConsumerConfig{
		Expected:         authjwt.Expectations{Issuer: "https://auth.example.com", Audience: "orders", Mode: authjwt.Strict},
		JWKSURL:          "https://auth.example.com/.well-known/jwks.json",
		IntrospectionURL: "https://auth.example.com/api/v1/internal/auth/token/introspect",
		ClientID:         "orders-api", ClientSecret: os.Getenv("ORDERS_AUTH_SERVICE_SECRET"),
	})
	if err != nil {
		return
	} // Fail startup; never log the config or credentials.
	defer consumer.Close()
	read, err := authjwt.RequirePermissions("orders.read")
	if err != nil {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("GET /orders", consumer.Middleware(read(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := authjwt.PrincipalFromContext(r.Context())
		// Query orders owned by p.UserID(); object/field filtering belongs to this backend.
		_ = p.UserID()
		w.WriteHeader(http.StatusNoContent)
	}))))
	server := &http.Server{Addr: ":9443", Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute}
	_ = server // Serve with deployment TLS/ingress and graceful shutdown in the owning application.
}

func ExampleConsumerConfig_local() {
	cfg := authjwt.ConsumerConfig{
		Expected: authjwt.Expectations{Issuer: "https://auth.example.com", Audience: "reports", Mode: authjwt.Local},
		JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
	}
	// No introspection URL or service credential; Auth must issue this audience in explicit local mode.
	consumer, err := authjwt.NewConsumer(context.Background(), cfg)
	if err != nil {
		return
	}
	defer consumer.Close()
	_ = consumer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := authjwt.PrincipalFromContext(r.Context())
		_ = p.UserID()
		w.WriteHeader(http.StatusNoContent)
	}))
}
