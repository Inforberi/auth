package service

import (
	"encoding/json"
	"html"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (s *ProvisionService) prepareInvitation(email string) (domain.Invitation, error) {
	token, err := changeToken()
	if err != nil {
		return domain.Invitation{}, err
	}
	link, err := changeLink(s.cfg.URL, token)
	if err != nil {
		return domain.Invitation{}, err
	}
	plain, err := json.Marshal(emailMessage{
		To: email, Subject: "Приглашение в аккаунт",
		Body: `<p>Задайте пароль для нового аккаунта: <a href="` + html.EscapeString(link) + `">активировать аккаунт</a>. Переход по ссылке не активирует аккаунт автоматически. Если вы не ожидали приглашение, проигнорируйте письмо.</p>`,
	})
	if err != nil {
		return domain.Invitation{}, err
	}
	payload, err := s.account.cipher.Seal(plain)
	return domain.Invitation{Digest: tokenDigest(token), Payload: payload}, err
}
