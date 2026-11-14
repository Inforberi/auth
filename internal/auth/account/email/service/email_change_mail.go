package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func (s *EmailChangeService) prepareChange(ctx context.Context, oldEmail, newEmail string) (domain.EmailChangeIntent, error) {
	ttl, recoveryTTL, protectionTTL := s.cfg.TTL, s.cfg.RecoveryTTL, s.cfg.ProtectionTTL
	if s.cfg.LifetimeSource != nil {
		var err error
		ttl, recoveryTTL, protectionTTL, err = s.cfg.LifetimeSource(ctx)
		if err != nil {
			return domain.EmailChangeIntent{}, err
		}
	}
	confirmURL, reportURL, recoveryURL := s.cfg.ConfirmURL, s.cfg.ReportURL, s.cfg.RecoveryURL
	if s.cfg.URLSource != nil {
		var err error
		confirmURL, reportURL, recoveryURL, err = s.cfg.URLSource(ctx)
		if err != nil {
			return domain.EmailChangeIntent{}, err
		}
	}
	confirm, err := accountservice.NewEmailToken()
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	report, err := accountservice.NewEmailToken()
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	confirmLink, err := accountservice.EmailTokenLink(confirmURL, confirm)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	reportLink, err := accountservice.EmailTokenLink(reportURL, report)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	seal := func(to, subject, body string) ([]byte, error) {
		plain, err := json.Marshal(accountservice.EmailMessage{To: to, Subject: subject, Body: body})
		if err != nil {
			return nil, err
		}
		return s.cipher.Seal(plain)
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
	recovery, err := accountservice.NewEmailToken()
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	recoveryLink, err := accountservice.EmailTokenLink(recoveryURL, recovery)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	recoveryPayload, err := seal(oldEmail, "Восстановление защищённого аккаунта", `<p>Задайте новый пароль и верните прежний адрес входа: <a href="`+html.EscapeString(recoveryLink)+`">восстановить доступ</a>. Ссылка работает только после защитной блокировки и не выполняет вход автоматически.</p>`)
	if err != nil {
		return domain.EmailChangeIntent{}, err
	}
	now := time.Now().UTC()
	return domain.EmailChangeIntent{ConfirmDigest: accountservice.TokenDigest(confirm), ReportDigest: accountservice.TokenDigest(report), ConfirmPayload: confirmPayload, NoticePayload: notice, CompletionPayload: completion, RecoveryDigest: accountservice.TokenDigest(recovery), RecoveryPayload: recoveryPayload, RecoveryTTL: recoveryTTL, ExpiresAt: now.Add(ttl), ProtectUntil: now.Add(protectionTTL)}, nil
}

func validChangeToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == token
}
