package mfahttp

import (
	"net/http"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func RequestProof(w http.ResponseWriter, r *http.Request) (mfaservice.Proof, bool) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
		return mfaservice.Proof{}, false
	}
	return mfaservice.Proof{UserID: auth.UserID, TokenHash: auth.TokenHash, AuthVersion: auth.AuthVersion}, true
}

func ActionProof(w http.ResponseWriter, r *http.Request) (mfaservice.Proof, bool) {
	proof, ok := RequestProof(w, r)
	if !ok {
		return mfaservice.Proof{}, false
	}
	if r.Body != nil && r.Body != http.NoBody {
		var input struct{}
		if err := httpx.DecodeJSON(w, r, &input); err != nil {
			httpx.Error(w, 400, "invalid_json", "this action accepts no fields")
			return mfaservice.Proof{}, false
		}
	}
	return proof, true
}
