package http

import (
	"net/http"

	oidchttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/transport/http"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
)

type (
	CallbackResponse     = oidchttp.CallbackResponse
	MFAChallengeResponse = mfahttp.ChallengeResponse
)

// @Summary Complete Telegram OIDC login
// @Description Provider redirect bound to single-use state, PKCE, nonce and flow cookie. Login sets __Host-session; linking requires the unchanged fresh session and never creates or replaces it. No email auto-merge. Restart after a failed or lost callback.
// @Tags Auth
// @Param code query string true "Authorization code"
// @Param state query string true "Single-use state"
// @Produce json
// @Success 200 {object} oidchttp.CallbackResponse
// @Success 202 {object} MFAChallengeResponse "MFA required; browser binding cookie, no session issued"
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse "codes: fresh_auth_required, registration_disabled"
// @Failure 404 {object} httpx.ErrorResponse "code: method_disabled"
// @Failure 409 {object} httpx.ErrorResponse "identity_conflict"
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/auth/telegram/callback [get]
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) { h.Handler.Callback(w, r) }
