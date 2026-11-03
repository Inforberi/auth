package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type PreferenceUpdate struct {
	mfaservice.Proof
	ExpectedVersion int64
	Method          domain.Method
}

type PreferenceRepository interface {
	ReadMFAPreference(context.Context, mfaservice.Proof) (domain.Preference, error)
	UpdateMFAPreference(context.Context, PreferenceUpdate) (domain.Preference, error)
}

type PreferenceConfig struct {
	UserChangesPerMinute, ProjectChangesPerMinute int
}

type Preferences struct {
	repo   PreferenceRepository
	cipher mfaservice.Cipher
	limits mfaservice.Limiter
	cfg    PreferenceConfig
}

func NewPreferences(repo PreferenceRepository, cipher mfaservice.Cipher, limits mfaservice.Limiter, cfg PreferenceConfig) (*Preferences, error) {
	if repo == nil || cipher == nil || limits == nil || cfg.UserChangesPerMinute < 1 || cfg.ProjectChangesPerMinute < 1 {
		return nil, domain.ErrUnavailable
	}
	return &Preferences{repo: repo, cipher: cipher, limits: limits, cfg: cfg}, nil
}

func (s *Preferences) Read(ctx context.Context, proof mfaservice.Proof) (domain.Preference, error) {
	if err := proof.Validate(); err != nil {
		return domain.Preference{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadMFAPreference(ctx, proof)
}

func (s *Preferences) Update(ctx context.Context, input PreferenceUpdate) (domain.Preference, error) {
	if err := input.Validate(); err != nil {
		return domain.Preference{}, err
	}
	if input.ExpectedVersion < 0 || !domain.ValidPreference(input.Method) {
		return domain.Preference{}, domain.ErrInvalidPreference
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := mfaservice.AdmitBudgets(ctx, s.limits, []mfaservice.Budget{
		{Key: s.cipher.Digest("mfa-preference:user:" + string(input.UserID)), Count: s.cfg.UserChangesPerMinute},
		{Key: s.cipher.Digest("mfa-preference:project"), Count: s.cfg.ProjectChangesPerMinute},
	}); err != nil {
		return domain.Preference{}, err
	}
	return s.repo.UpdateMFAPreference(ctx, input)
}
