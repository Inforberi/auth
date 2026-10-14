package service

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/delivery"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type RecoveryDeliveryRepository interface {
	ClaimRecoveryDelivery(context.Context) (*domain.RecoveryDelivery, error)
	FinishRecoveryDelivery(context.Context, domain.RecoveryDelivery, bool) error
}

type RecoveryMailer interface {
	SendContext(context.Context, string, string, string) error
}

type RecoveryDelivery struct {
	repo   RecoveryDeliveryRepository
	cipher Cipher
	mail   RecoveryMailer
}

type recoveryNotice struct {
	To        string    `json:"to"`
	RequestID string    `json:"request_id"`
	At        time.Time `json:"at"`
}

func NewRecoveryDelivery(repo RecoveryDeliveryRepository, cipher Cipher, mail RecoveryMailer) (*RecoveryDelivery, error) {
	if repo == nil || cipher == nil || mail == nil {
		return nil, errors.New("invalid MFA recovery delivery dependencies")
	}
	return &RecoveryDelivery{repo: repo, cipher: cipher, mail: mail}, nil
}

func sealRecoveryNotice(cipher Cipher, email, request string, at time.Time) ([]byte, error) {
	plain, err := json.Marshal(recoveryNotice{To: email, RequestID: request, At: at})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return cipher.Seal(plain)
}

func (s *RecoveryDelivery) DeliverOne(ctx context.Context) (bool, error) {
	claimCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	job, err := s.repo.ClaimRecoveryDelivery(claimCtx)
	stop()
	if err != nil || job == nil {
		return false, err
	}
	err = domain.ErrRecoveryDelivery
	if !job.Exhausted {
		deliveryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = s.send(deliveryCtx, job.Payload)
		cancel()
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if finishErr := s.repo.FinishRecoveryDelivery(finishCtx, *job, err == nil); finishErr != nil {
		return true, finishErr
	}
	return true, err
}

func (s *RecoveryDelivery) send(ctx context.Context, payload []byte) error {
	plain, err := s.cipher.Open(payload)
	if err != nil {
		return domain.ErrRecoveryDelivery
	}
	defer clear(plain)
	var notice recoveryNotice
	if err := json.Unmarshal(plain, &notice); err != nil {
		return domain.ErrRecoveryDelivery
	}
	body := `<p>Второй фактор вашего аккаунта заменён через операторское восстановление.</p><p>Время: ` +
		html.EscapeString(notice.At.UTC().Format(time.RFC3339)) + `. Запрос: ` + html.EscapeString(notice.RequestID) +
		`.</p><p>Старые сессии и резервные коды отозваны. Если это были не вы, немедленно свяжитесь с администратором по известному вам каналу.</p>`
	if err := s.mail.SendContext(ctx, notice.To, "Изменение второго фактора", body); err != nil {
		return domain.ErrRecoveryDelivery
	}
	return nil
}

func (s *RecoveryDelivery) RunDelivery(ctx context.Context, report func(error)) {
	delivery.Run(ctx, s.DeliverOne, func(error) { report(domain.ErrRecoveryDelivery) })
}
