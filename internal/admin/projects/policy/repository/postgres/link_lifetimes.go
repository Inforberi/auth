package postgres

import (
	"context"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

type LinkLifetimeSettings struct {
	Version int64                       `json:"version"`
	Policy  settings.LinkLifetimePolicy `json:"policy"`
	Source  settings.SourceMetadata     `json:"source"`
}

func (r *RuntimeAuthPolicy) WithLinkLifetimeBaseline(baseline settings.LinkLifetimePolicy, resend int64) *RuntimeAuthPolicy {
	r.linkLifetimes, r.verificationResendSeconds = baseline, resend
	return r
}

func (r *RuntimeAuthPolicy) ReadProjectLinkLifetimes(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (LinkLifetimeSettings, error) {
	return readVersionedSettings(ctx, r, actor, target, settingspg.New(nil).LinkLifetimePolicy(), r.linkLifetimes, linkLifetimeResponse)
}

func (r *RuntimeAuthPolicy) UpdateProjectLinkLifetimes(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, expected int64, policy settings.LinkLifetimePolicy) (LinkLifetimeSettings, error) {
	if expected < 1 || policy.Validate(r.verificationResendSeconds) != nil {
		return LinkLifetimeSettings{}, settings.ErrInvalidLinkLifetime
	}
	return writeVersionedSettings(ctx, r, actor, target, settingspg.New(nil).LinkLifetimePolicy(), expected, r.linkLifetimes, policy, linkLifetimeResponse)
}

func linkLifetimeResponse(snapshot settingspg.PolicySnapshot[settings.LinkLifetimePolicy], mode settings.SourceMode) LinkLifetimeSettings {
	return LinkLifetimeSettings{Version: snapshot.Version, Policy: snapshot.Policy, Source: mode.Metadata()}
}
