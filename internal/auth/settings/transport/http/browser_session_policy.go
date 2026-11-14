//nolint:dupl // Concrete request and response types are required by the Swagger generator.
package settingshttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessions "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type BrowserSessionPolicyDTO struct {
	IdleSeconds             int64 `json:"idleSeconds"`
	AbsoluteSeconds         int64 `json:"absoluteSeconds"`
	RefreshThresholdSeconds int64 `json:"refreshThresholdSeconds"`
	AdminIdleSeconds        int64 `json:"adminIdleSeconds"`
	AdminAbsoluteSeconds    int64 `json:"adminAbsoluteSeconds"`
	AdminActivitySeconds    int64 `json:"adminActivitySeconds"`
}

type BrowserSessionPolicyView struct {
	Version int64                   `json:"version"`
	Policy  BrowserSessionPolicyDTO `json:"policy"`
	Source  domain.SourceMetadata   `json:"source"`
}

type BrowserSessionPolicyRequest struct {
	ExpectedVersion int64                    `json:"expectedVersion"`
	Policy          *BrowserSessionPolicyDTO `json:"policy"`
}

type BrowserSessionPolicyHandler struct {
	ReadPolicy   func(context.Context, accessservice.Principal) (BrowserSessionPolicyView, error)
	UpdatePolicy func(context.Context, accessservice.Principal, int64, sessions.BrowserPolicy) (BrowserSessionPolicyView, error)
	Log          *zap.Logger
}

// @Summary Read standalone browser session policy
// @Success 200 {object} BrowserSessionPolicyView
// @Router /api/v1/admin/auth/settings/sessions [get]
func (h *BrowserSessionPolicyHandler) Read(w http.ResponseWriter, r *http.Request) {
	servePolicyRead(w, r, h.ReadPolicy, policyResponse[BrowserSessionPolicyView](h.Log, "browser_session_policy", sessions.ErrInvalidBrowserPolicy, "invalid browser session policy"))
}

// @Summary Change standalone browser session policy
// @Accept json
// @Param body body BrowserSessionPolicyRequest true "Complete policy and current version"
// @Success 200 {object} BrowserSessionPolicyView
// @Failure 409 {object} PolicyErrorResponse
// @Router /api/v1/admin/auth/settings/sessions [post]
func (h *BrowserSessionPolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	servePolicyUpdate(w, r, h.UpdatePolicy, policyResponse[BrowserSessionPolicyView](h.Log, "browser_session_policy", sessions.ErrInvalidBrowserPolicy, "invalid browser session policy"))
}
