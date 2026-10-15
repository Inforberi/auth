package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type UserContactResponse struct {
	Email      string     `json:"email"`
	VerifiedAt *time.Time `json:"verifiedAt"`
} // @name account_http.UserContactResponse

type UserRoleResponse struct {
	ID      accessdomain.RoleID `json:"id" swaggertype:"string"`
	Key     string              `json:"key"`
	Name    string              `json:"name"`
	System  bool                `json:"system"`
	Version int64               `json:"version"`
} // @name account_http.UserRoleResponse

type UserDetailResponse struct {
	UserSummaryResponse
	AuthVersion               domain.AuthVersion    `json:"authVersion" swaggertype:"integer"`
	AccessVersion             int64                 `json:"accessVersion"`
	DeletedAt                 *time.Time            `json:"deletedAt"`
	PasswordConfigured        bool                  `json:"passwordConfigured"`
	TemporaryPasswordRequired bool                  `json:"temporaryPasswordRequired"`
	MFAEnrolled               bool                  `json:"mfaEnrolled"`
	Contacts                  []UserContactResponse `json:"contacts"`
	ExternalIssuers           []string              `json:"externalIssuers"`
	Roles                     []UserRoleResponse    `json:"roles"`
} // @name account_http.UserDetailResponse

// @Summary Read a user card
// @Description Requires current accounts.users.read, not a user UUID claim or management permission alone. Includes stored status/versions, contact verification, configured password/MFA, external issuers and role metadata. Configuration is not a guarantee of usable login or effective access. No password hash, subject, token, MFA secret or recovery codes. UUID lookup also supports retained soft-deleted users without restoring them. Contacts/providers/roles bounded to 32; overflow is an explicit conflict, not silent truncation.
// @Tags Admin Users
// @Produce json
// @Param id path string true "User UUID"
// @Success 200 {object} UserDetailResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users/{id} [get]
func (h *UserDirectoryHandler) Read(w http.ResponseWriter, r *http.Request) {
	actor, ok := accountActor(w, r)
	if !ok {
		return
	}
	user, err := h.service.Read(r.Context(), actor, domain.UserID(chi.URLParam(r, "id")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	response := UserDetailResponse{
		UserSummaryResponse: userSummaryResponse(user.UserSummary), AuthVersion: user.AuthVersion, AccessVersion: user.AccessVersion, DeletedAt: user.DeletedAt,
		PasswordConfigured: user.PasswordConfigured, TemporaryPasswordRequired: user.TemporaryPasswordRequired, MFAEnrolled: user.MFAEnrolled,
		Contacts: make([]UserContactResponse, 0, len(user.Contacts)), ExternalIssuers: user.ExternalIssuers, Roles: make([]UserRoleResponse, 0, len(user.Roles)),
	}
	if response.ExternalIssuers == nil {
		response.ExternalIssuers = []string{}
	}
	for _, contact := range user.Contacts {
		response.Contacts = append(response.Contacts, UserContactResponse{Email: contact.Email, VerifiedAt: contact.VerifiedAt})
	}
	for _, role := range user.Roles {
		response.Roles = append(response.Roles, UserRoleResponse{ID: role.ID, Key: role.Key, Name: role.Name, System: role.System, Version: role.Version})
	}
	httpx.JSON(w, 200, response)
}
