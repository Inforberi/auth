package mfahttp

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

var telegramErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidTelegramPreparation, 400, "invalid_telegram_factor", "invalid Telegram channel proof"),
	httpx.MatchError(domain.ErrInvalidPreference, 400, "invalid_mfa_preference", "invalid MFA preference"),
}, emailErrors...)

func RespondTelegramError(w http.ResponseWriter, r *http.Request, log *zap.Logger, err error) {
	respondError(w, r, log, err, telegramErrors)
}
