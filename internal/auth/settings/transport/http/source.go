package settingshttp

import (
	"net/http"

	configuration "github.com/Inforberi/financial-intelligence/internal/auth/settings/configuration/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func WithConfigurationSource(next http.Handler, mode domain.SourceMode) http.Handler {
	if mode.Effective() == domain.SourceAPI {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(configuration.WithSourceMode(r.Context(), mode)))
	})
}
