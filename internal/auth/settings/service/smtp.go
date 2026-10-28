package service

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type SMTPStored struct {
	domain.SMTPSnapshot
	Password []byte `json:"-"`
}

type SMTPUpdate struct {
	Actor           accessservice.Principal
	ExpectedVersion int64
	Config          domain.SMTPConfig
	Password        []byte `json:"-"`
	PasswordSet     bool
}

type SMTPRepository interface {
	LoadSMTP(context.Context) (SMTPStored, error)
	InitializeSMTP(context.Context, SMTPStored) (SMTPStored, error)
	ReadSMTP(context.Context, accessservice.Principal) (domain.SMTPSnapshot, error)
	UpdateSMTP(context.Context, SMTPUpdate) (domain.SMTPSnapshot, error)
	AuthorizeSMTPTest(context.Context, accessservice.Principal, int64) (SMTPStored, error)
}

type SMTPCipher interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
}

type SMTPProbe func(context.Context, domain.SMTPConfig, string) error

type SMTPLimiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
}

type SMTPTestGate struct{ slots chan struct{} }

func NewSMTPTestGate() *SMTPTestGate { return &SMTPTestGate{slots: make(chan struct{}, 2)} }

type SMTP struct {
	repo   SMTPRepository
	cipher SMTPCipher
	probe  SMTPProbe
	limits SMTPLimiter
	policy smtpPolicy
	tests  chan struct{}
}

func NewSMTP(repo SMTPRepository, cipher SMTPCipher, probe SMTPProbe, limits SMTPLimiter, allowed []string, requireTLS bool) (*SMTP, error) {
	return NewSMTPWithTestGate(repo, cipher, probe, limits, allowed, requireTLS, NewSMTPTestGate())
}

func NewSMTPWithTestGate(repo SMTPRepository, cipher SMTPCipher, probe SMTPProbe, limits SMTPLimiter, allowed []string, requireTLS bool, gate *SMTPTestGate) (*SMTP, error) {
	if repo == nil || cipher == nil || probe == nil || limits == nil || gate == nil || gate.slots == nil {
		return nil, domain.ErrInvalidSMTP
	}
	policy, err := newSMTPPolicy(allowed, requireTLS)
	if err != nil {
		return nil, err
	}
	return &SMTP{repo: repo, cipher: cipher, probe: probe, limits: limits, policy: policy, tests: gate.slots}, nil
}

func (s *SMTP) Read(ctx context.Context, actor accessservice.Principal) (domain.SMTPSnapshot, error) {
	if actor.Validate() != nil {
		return domain.SMTPSnapshot{}, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadSMTP(ctx, actor)
}
