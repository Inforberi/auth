package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

type changeRepository struct {
	snapshot                 domain.EmailChangeSnapshot
	intent                   domain.EmailChangeIntent
	email, session, consumed string
	reads, writes            int
	err                      error
}

func (r *changeRepository) EmailChangeSnapshot(context.Context, domain.UserID) (domain.EmailChangeSnapshot, error) {
	r.reads++
	return r.snapshot, r.err
}

func (r *changeRepository) RequestEmailChange(ctx context.Context, snapshot domain.EmailChangeSnapshot, session, email string, intent domain.EmailChangeIntent) error {
	if _, ok := ctx.Deadline(); !ok || snapshot != r.snapshot {
		return errors.New("missing deadline or changed credential snapshot")
	}
	r.writes++
	r.session, r.email, r.intent = session, email, intent
	return r.err
}

func (r *changeRepository) ConfirmEmailChange(_ context.Context, digest string) error {
	r.consumed = "confirm:" + digest
	return r.err
}

func (r *changeRepository) ReportEmailChange(_ context.Context, digest string) error {
	r.consumed = "report:" + digest
	return r.err
}

type changeHasher struct {
	calls int
	err   error
}

func (h *changeHasher) Compare(_ context.Context, password, expected string) error {
	h.calls++
	if password != "current-password" || expected != "current-hash" {
		return errors.New("wrong password")
	}
	return h.err
}

func TestEmailChangeService(t *testing.T) {
	account, deliveries, limits, mail, cipher := fixture(t)
	r := &changeRepository{snapshot: domain.EmailChangeSnapshot{UserID: "11111111-1111-4111-8111-111111111111", Email: "old@example.com", PasswordHash: "current-hash", AuthVersion: 1}}
	hash := &changeHasher{}
	cfg := service.EmailChangeConfig{Enabled: true, ConfirmURL: "https://example.com/change", ReportURL: "https://example.com/report", RecoveryURL: "https://example.com/recover", RecoveryTTL: 30 * time.Minute, TTL: 30 * time.Minute, ProtectionTTL: 24 * time.Hour}
	if err := cfg.Validate(true); err != nil {
		t.Fatal(err)
	}
	s := service.NewEmailChange(r, hash, account, cfg)
	ctx := context.Background()
	if err := s.Request(ctx, r.snapshot.UserID, strings.Repeat("a", 64), " NEW@example.com ", "current-password", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if r.email != "new@example.com" || r.session != strings.Repeat("a", 64) || r.writes != 1 || hash.calls != 1 {
		t.Fatal("request contract", r, hash)
	}
	var confirmToken, reportToken, recoveryToken string
	for index, payload := range [][]byte{r.intent.ConfirmPayload, r.intent.NoticePayload, r.intent.CompletionPayload, r.intent.RecoveryPayload} {
		plain, err := cipher.Open(payload)
		if err != nil {
			t.Fatal(err)
		}
		var message struct{ To, Subject, Body string }
		if err := json.Unmarshal(plain, &message); err != nil {
			t.Fatal(err)
		}
		to := "old@example.com"
		if index == 0 {
			to = "new@example.com"
		}
		if message.To != to || message.Subject == "" || !strings.Contains(message.Body, "#token=") {
			t.Fatal("mail contract", message)
		}
		start := strings.Index(message.Body, "#token=") + 7
		token := message.Body[start : start+43]
		switch {
		case index == 0:
			confirmToken = token
		case index == 3:
			recoveryToken = token
		case reportToken != "" && token != reportToken:
			t.Fatal("completion replaced security token")
		default:
			reportToken = token
		}
		deliveries.job = &domain.VerificationDelivery{EmailChange: true, Payload: payload}
		if err := account.DeliverOne(ctx); err != nil || mail.to != to {
			t.Fatal("reused delivery", err)
		}
	}
	if confirmToken == reportToken || recoveryToken == confirmToken || recoveryToken == reportToken || r.intent.ConfirmDigest == r.intent.ReportDigest || r.intent.RecoveryDigest == r.intent.ReportDigest {
		t.Fatal("purposes share token")
	}
	if err := s.Confirm(ctx, confirmToken, "127.0.0.1"); err != nil || !strings.HasPrefix(r.consumed, "confirm:") {
		t.Fatal(err)
	}
	if err := s.Report(ctx, reportToken, "127.0.0.1"); err != nil || !strings.HasPrefix(r.consumed, "report:") {
		t.Fatal(err)
	}
	if strings.Contains(r.consumed, reportToken) {
		t.Fatal("raw token reached repository")
	}
	for _, token := range []string{"", strings.Repeat("x", 129), "not-canonical"} {
		if err := s.Confirm(ctx, token, "ip"); !errors.Is(err, domain.ErrInvalidEmailChange) {
			t.Fatal(err)
		}
	}
	reads, writes, calls := r.reads, r.writes, hash.calls
	if err := s.Request(ctx, r.snapshot.UserID, strings.Repeat("a", 64), "bad", "current-password", "ip"); !errors.Is(err, domain.ErrEmailInvalid) {
		t.Fatal(err)
	}
	if r.reads != reads || r.writes != writes || hash.calls != calls {
		t.Fatal("invalid email contacted dependencies")
	}
	if err := s.Request(ctx, r.snapshot.UserID, strings.Repeat("a", 64), "new@example.com", "wrong", "ip"); !errors.Is(err, domain.ErrFreshAuthRequired) || r.writes != writes {
		t.Fatal("wrong password queued change", err)
	}
	limits.err = errors.New("limiter unavailable")
	reads = r.reads
	if err := s.Request(ctx, r.snapshot.UserID, strings.Repeat("a", 64), "new@example.com", "current-password", "ip"); !errors.Is(err, limits.err) || r.reads != reads {
		t.Fatal("limiter fail open", err)
	}
}

func TestEmailChangeConfig(t *testing.T) {
	cfg := service.EmailChangeConfig{Enabled: true, ConfirmURL: "https://example.com/change", ReportURL: "https://example.com/report", RecoveryURL: "https://example.com/recover", RecoveryTTL: 30 * time.Minute, TTL: 30 * time.Minute, ProtectionTTL: 24 * time.Hour}
	for name, mutate := range map[string]func(*service.EmailChangeConfig){
		"credentials":          func(c *service.EmailChangeConfig) { c.ReportURL = "https://user:secret@example.com/report" },
		"query":                func(c *service.EmailChangeConfig) { c.ConfirmURL += "?token=x" },
		"http production":      func(c *service.EmailChangeConfig) { c.ConfirmURL = "http://example.com/change" },
		"ttl":                  func(c *service.EmailChangeConfig) { c.TTL = 2 * time.Hour },
		"protection":           func(c *service.EmailChangeConfig) { c.ProtectionTTL = time.Minute },
		"missing recovery URL": func(c *service.EmailChangeConfig) { c.RecoveryURL = "" },
		"recovery URL query":   func(c *service.EmailChangeConfig) { c.RecoveryURL += "?token=x" },
		"recovery TTL":         func(c *service.EmailChangeConfig) { c.RecoveryTTL = 2 * time.Hour },
	} {
		t.Run(name, func(t *testing.T) {
			c := cfg
			mutate(&c)
			if c.Validate(true) == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	if err := (service.EmailChangeConfig{}).Validate(true); err != nil {
		t.Fatal("disabled profile requires settings", err)
	}
}
