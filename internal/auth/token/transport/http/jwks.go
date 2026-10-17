package http

import "net/http"

type JWKSResponse struct {
	Keys []PublicKey `json:"keys"`
} // @name token_http.JWKSResponse

type PublicKey struct {
	Type       string   `json:"kty"`
	Curve      string   `json:"crv"`
	X          string   `json:"x"`
	Y          string   `json:"y"`
	ID         string   `json:"kid"`
	Algorithm  string   `json:"alg"`
	Use        string   `json:"use"`
	Operations []string `json:"key_ops,omitempty"`
} // @name token_http.PublicKey

// @Summary Public JWT verification keys
// @Description Public-only deployment key set. Contains no private signing material. Not an authorization decision. Keys are operator-controlled and loaded on startup.
// @Tags Tokens
// @Produce json
// @Success 200 {object} JWKSResponse
// @Success 304 "unchanged"
// @Router /.well-known/jwks.json [get]
// @Router /.well-known/jwks.json [head]
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=30, must-revalidate")
	w.Header().Set("ETag", h.etag)
	if r.Header.Get("If-None-Match") == h.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(h.public) //nolint:gosec // A disconnected client cannot receive a second response.
}
