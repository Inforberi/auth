package service

import (
	"context"
	"net"
	"strconv"
	"strings"
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

type SMTP struct {
	repo       SMTPRepository
	cipher     SMTPCipher
	probe      SMTPProbe
	limits     SMTPLimiter
	targets    map[string]bool
	requireTLS bool
	tests      chan struct{}
}

func NewSMTP(repo SMTPRepository, cipher SMTPCipher, probe SMTPProbe, limits SMTPLimiter, allowed []string, requireTLS bool) (*SMTP, error) {
	if repo == nil || cipher == nil || probe == nil || limits == nil || len(allowed) == 0 || len(allowed) > 16 {
		return nil, domain.ErrInvalidSMTP
	}
	s := &SMTP{repo: repo, cipher: cipher, probe: probe, limits: limits, targets: make(map[string]bool), requireTLS: requireTLS, tests: make(chan struct{}, 2)}
	for _, target := range allowed {
		host, port, err := net.SplitHostPort(strings.TrimSpace(target))
		number, parseErr := strconv.Atoi(port)
		candidate := domain.SMTPConfig{Host: host, Port: number, Domain: "example.com", From: "auth@example.com"}
		if err != nil || parseErr != nil || candidate.Validate() != nil {
			return nil, domain.ErrInvalidSMTP
		}
		s.targets[smtpTarget(candidate)] = true
	}
	return s, nil
}

func smtpTarget(c domain.SMTPConfig) string {
	return net.JoinHostPort(strings.ToLower(c.Host), strconv.Itoa(c.Port))
}

func (s *SMTP) validate(config domain.SMTPConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if !s.targets[smtpTarget(config)] || s.requireTLS && !config.RequireTLS {
		return domain.ErrInvalidSMTP
	}
	return nil
}

func (s *SMTP) Read(ctx context.Context, actor accessservice.Principal) (domain.SMTPSnapshot, error) {
	if actor.Validate() != nil {
		return domain.SMTPSnapshot{}, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadSMTP(ctx, actor)
}
