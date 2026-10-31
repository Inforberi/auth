package authjwt

import (
	"net/http"
	"time"
)

// RequireStrongMFA runs after Consumer.Middleware. Signature-only mode keeps its revocation window.
func RequireStrongMFA(maxAge time.Duration) (func(http.Handler) http.Handler, error) {
	if maxAge <= 0 || maxAge > 15*time.Minute {
		return nil, ErrConfiguration
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			now := time.Now()
			if !ok || !p.expiresAt.After(now) {
				writeBearerError(w, ErrInvalidToken)
				return
			}
			if !p.strongMFAAt(now, maxAge) {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				if _, err := w.Write([]byte(`{"error":"strong_mfa_required"}`)); err != nil {
					return
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

func (p Principal) strongMFAAt(now time.Time, maxAge time.Duration) bool {
	if p.mfaVerifiedAt.IsZero() || p.mfaVerifiedAt.After(now) || now.Sub(p.mfaVerifiedAt) >= maxAge || len(p.methods) != 2 {
		return false
	}
	primary, factor := false, false
	for _, method := range p.methods {
		switch method {
		case "pwd", "emailotp", "oidc":
			primary = true
		case "otp", "recovery":
			factor = true
		default:
			return false
		}
	}
	return primary && factor
}
