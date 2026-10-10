package service

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/url"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (s *EmailChangeService) prepareChange(oldEmail, newEmail string) (domain.EmailChangeIntent, error) {
	confirm, err := changeToken()
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	report, err := changeToken()
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	confirmLink, err := changeLink(s.cfg.ConfirmURL, confirm)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	reportLink, err := changeLink(s.cfg.ReportURL, report)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	seal := func(to, subject, body string) ([]byte, error) {
		plain, err := json.Marshal(emailMessage{To: to, Subject: subject, Body: body})
		if err != nil {
			return nil, err
		}
		return s.account.cipher.Seal(plain)
	}
	confirmPayload, err := seal(newEmail, "Подтверждение смены email", `<p>Подтвердите новый адрес: <a href="`+html.EscapeString(confirmLink)+`">подтвердить смену</a>.</p>`)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	warning := `<p>Если это не вы: <a href="` + html.EscapeString(reportLink) + `">защитить аккаунт</a>. Переход только открывает страницу; действие требует подтверждения.</p>`
	notice, err := seal(oldEmail, "Запрошена смена email", `<p>Запрошена смена адреса входа на `+html.EscapeString(newEmail)+`.</p>`+warning)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	completion, err := seal(oldEmail, "Email изменён", `<p>Адрес входа изменён на `+html.EscapeString(newEmail)+`.</p>`+warning)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	recovery, err := changeToken()
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	recoveryLink, err := changeLink(s.cfg.RecoveryURL, recovery)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	recoveryPayload, err := seal(oldEmail, "Восстановление защищённого аккаунта", `<p>Задайте новый пароль и верните прежний адрес входа: <a href="`+html.EscapeString(recoveryLink)+`">восстановить доступ</a>. Ссылка работает только после защитной блокировки и не выполняет вход автоматически.</p>`)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	now := time.Now().UTC()
	return domain.EmailChangeIntent{ConfirmDigest: tokenDigest(confirm), ReportDigest: tokenDigest(report), ConfirmPayload: confirmPayload, NoticePayload: notice, CompletionPayload: completion, RecoveryDigest: tokenDigest(recovery), RecoveryPayload: recoveryPayload, RecoveryTTL: s.cfg.RecoveryTTL, ExpiresAt: now.Add(s.cfg.TTL), ProtectUntil: now.Add(s.cfg.ProtectionTTL)}, nil
}

func changeToken() (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(secret[:]), nil
}

func validChangeToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == token
}

func changeLink(address, token string) (string, error) {
	// Startup validation supplies trusted URLs; fragments keep tokens out of access logs/referrers.
	u, err := url.Parse(address)
	if err != nil {
		return "", err
	}
	u.Fragment = "token=" + token
	return u.String(), nil
}
