package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

type ExchangeService interface {
	Exchange(context.Context, service.ExchangeInput) (*service.ExchangeResult, error)
}

type Handler struct {
	service ExchangeService
	public  []byte
	etag    string
	log     *zap.Logger
}

// public must come from the signing owner's public-only JWKS, never a private key file.
func New(svc ExchangeService, public []byte, log *zap.Logger) *Handler {
	sum := sha256.Sum256(public)
	return &Handler{service: svc, public: slices.Clone(public), etag: `"` + hex.EncodeToString(sum[:]) + `"`, log: log}
}
