package settingshttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type CredentialLifetimePolicyDTO struct {
	MFAChallengeSeconds             int64 `json:"mfaChallengeSeconds"`
	FreshAuthSeconds                int64 `json:"freshAuthSeconds"`
	EmailBindingSeconds             int64 `json:"emailBindingSeconds"`
	InvitationSeconds               int64 `json:"invitationSeconds"`
	InvitationCooldownSeconds       int64 `json:"invitationCooldownSeconds"`
	TemporaryReissueCooldownSeconds int64 `json:"temporaryReissueCooldownSeconds"`
	TemporaryPasswordSeconds        int64 `json:"temporaryPasswordSeconds"`
	TemporarySetupSeconds           int64 `json:"temporarySetupSeconds"`
	EmailChangeSeconds              int64 `json:"emailChangeSeconds"`
	EmailChangeRecoverySeconds      int64 `json:"emailChangeRecoverySeconds"`
	EmailChangeProtectionSeconds    int64 `json:"emailChangeProtectionSeconds"`
}

type CredentialLifetimePolicyView struct {
	Version int64                       `json:"version"`
	Policy  CredentialLifetimePolicyDTO `json:"policy"`
	Source  domain.SourceMetadata       `json:"source"`
}

type CredentialLifetimePolicyRequest struct {
	ExpectedVersion int64                        `json:"expectedVersion"`
	Policy          *CredentialLifetimePolicyDTO `json:"policy"`
}

type CredentialLifetimePolicyHandler struct {
	ReadPolicy   func(context.Context, accessservice.Principal) (CredentialLifetimePolicyView, error)
	UpdatePolicy func(context.Context, accessservice.Principal, int64, domain.CredentialLifetimePolicy) (CredentialLifetimePolicyView, error)
	Log          *zap.Logger
}

// @Summary Read standalone credential lifetime policy
// @Success 200 {object} CredentialLifetimePolicyView
// @Router /api/v1/admin/auth/settings/credential-lifetimes [get]
func (h *CredentialLifetimePolicyHandler) Read(w http.ResponseWriter, r *http.Request) {
	servePolicyRead(w, r, h.ReadPolicy, policyResponse[CredentialLifetimePolicyView](h.Log, "credential_lifetime_policy", domain.ErrInvalidCredentialLifetime, "invalid credential lifetime policy"))
}

// @Summary Change standalone credential lifetime policy
// @Accept json
// @Param body body CredentialLifetimePolicyRequest true "Complete policy and current version"
// @Success 200 {object} CredentialLifetimePolicyView
// @Failure 409 {object} PolicyErrorResponse
// @Router /api/v1/admin/auth/settings/credential-lifetimes [post]
func (h *CredentialLifetimePolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	servePolicyUpdate(w, r, h.UpdatePolicy, policyResponse[CredentialLifetimePolicyView](h.Log, "credential_lifetime_policy", domain.ErrInvalidCredentialLifetime, "invalid credential lifetime policy"))
}
