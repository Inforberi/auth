package accounthttp

import (
	"net/http"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func Actor(w http.ResponseWriter, r *http.Request) (accessservice.Principal, bool) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
		return accessservice.Principal{}, false
	}
	return accessservice.Principal{UserID: auth.UserID, TokenHash: auth.TokenHash}, true
}
