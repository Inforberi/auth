package settingshttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type LinkLifetimePolicyDTO struct {
	VerificationSeconds int64 `json:"verificationSeconds"`
	ResetSeconds        int64 `json:"resetSeconds"`
}

type LinkLifetimePolicyView struct {
	Version int64                 `json:"version"`
	Policy  LinkLifetimePolicyDTO `json:"policy"`
	Source  domain.SourceMetadata `json:"source"`
}

type LinkLifetimePolicyRequest struct {
	ExpectedVersion int64                  `json:"expectedVersion"`
	Policy          *LinkLifetimePolicyDTO `json:"policy"`
}

type LinkLifetimePolicyHandler struct {
	ReadPolicy   func(context.Context, accessservice.Principal) (LinkLifetimePolicyView, error)
	UpdatePolicy func(context.Context, accessservice.Principal, int64, domain.LinkLifetimePolicy) (LinkLifetimePolicyView, error)
	Log          *zap.Logger
}

// @Summary Read standalone link lifetime policy
// @Success 200 {object} LinkLifetimePolicyView
// @ID getAdminAuthSettingsLinkLifetimes
// @Router /api/v1/admin/auth/settings/link-lifetimes [get]
func (h *LinkLifetimePolicyHandler) Read(w http.ResponseWriter, r *http.Request) {
	servePolicyRead(w, r, h.ReadPolicy, policyResponse[LinkLifetimePolicyView](h.Log, "link_lifetime_policy", domain.ErrInvalidLinkLifetime, "invalid link lifetime policy"))
}

// @Summary Change standalone link lifetime policy
// @Accept json
// @Param body body LinkLifetimePolicyRequest true "Complete policy and current version"
// @Success 200 {object} LinkLifetimePolicyView
// @Failure 409 {object} PolicyErrorResponse
// @ID postAdminAuthSettingsLinkLifetimes
// @Router /api/v1/admin/auth/settings/link-lifetimes [post]
func (h *LinkLifetimePolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	servePolicyUpdate(w, r, h.UpdatePolicy, policyResponse[LinkLifetimePolicyView](h.Log, "link_lifetime_policy", domain.ErrInvalidLinkLifetime, "invalid link lifetime policy"))
}
