package service

import (
	"encoding/json"
	"html"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type PrepareSecurityNotice func(email, event string, at time.Time) ([]byte, error)

type FactorMutation struct {
	Proof
	PrepareNotice PrepareSecurityNotice
}

type securityNotice struct {
	To        string    `json:"to"`
	Kind      string    `json:"kind,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	At        time.Time `json:"at"`
}

func sealSecurityNotice(cipher Cipher, email, kind, request string, at time.Time) ([]byte, error) {
	plain, err := json.Marshal(securityNotice{To: email, Kind: kind, RequestID: request, At: at})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return cipher.Seal(plain)
}

func sealRecoveryNotice(cipher Cipher, email, request string, at time.Time) ([]byte, error) {
	return sealSecurityNotice(cipher, email, "recovery", request, at)
}

func securityNoticeBody(notice securityNotice) (string, error) {
	if _, err := accountdomain.NewEmail(notice.To); err != nil || notice.At.IsZero() {
		return "", domain.ErrSecurityDelivery
	}
	var message string
	switch notice.Kind {
	case "", "recovery":
		if !accountdomain.ValidUserID(accountdomain.UserID(notice.RequestID)) {
			return "", domain.ErrSecurityDelivery
		}
		message = "Второй фактор вашего аккаунта заменён через операторское восстановление. Запрос: " + html.EscapeString(notice.RequestID) + "."
	case "telegram_factor_enabled":
		message = "Telegram подключён как второй фактор вашего аккаунта."
	case "telegram_factor_replaced":
		message = "Telegram-аккаунт для второго фактора изменён."
	case "telegram_factor_disabled":
		message = "Telegram отключён как второй фактор вашего аккаунта."
	default:
		return "", domain.ErrSecurityDelivery
	}
	if notice.Kind != "" && notice.Kind != "recovery" && notice.RequestID != "" {
		return "", domain.ErrSecurityDelivery
	}
	return "<p>" + message + "</p><p>Время: " + html.EscapeString(notice.At.UTC().Format(time.RFC3339)) +
		".</p><p>Старые сессии отозваны. Если это были не вы, немедленно свяжитесь с администратором по известному вам каналу.</p>", nil
}
