package service

import (
	"encoding/json"
	"html"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func (s *ProvisionService) prepareInvitation(email string) (domain.Invitation, error) {
	token, err := accountservice.NewEmailToken()
	if err != nil {
		return domain.Invitation{}, err
	}
	link, err := accountservice.EmailTokenLink(s.cfg.URL, token)
	if err != nil {
		return domain.Invitation{}, err
	}
	plain, err := json.Marshal(accountservice.EmailMessage{
		To: email, Subject: "Приглашение в аккаунт",
		Body: `<p>Задайте пароль для нового аккаунта: <a href="` + html.EscapeString(link) + `">активировать аккаунт</a>. Переход по ссылке не активирует аккаунт автоматически. Если вы не ожидали приглашение, проигнорируйте письмо.</p>`,
	})
	if err != nil {
		return domain.Invitation{}, err
	}
	payload, err := s.cipher.Seal(plain)
	return domain.Invitation{Digest: accountservice.TokenDigest(token), Payload: payload}, err
}
