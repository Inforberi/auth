package service

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type UserSummary struct {
	ID            domain.UserID
	Status        domain.Status
	CreatedAt     time.Time
	DisplayName   *string
	Email         *string
	EmailVerified bool
}

type UserListInput struct {
	Before string
	Status domain.Status
	Email  string
	Limit  int
}

type UserListQuery struct {
	BeforeCreatedAt *time.Time
	BeforeID        domain.UserID
	Status          domain.Status
	Email           string
	Limit           int
}

type UserPage struct {
	Users      []UserSummary
	NextCursor string
}

func (s *UserDirectory) List(ctx context.Context, actor accessservice.Principal, input UserListInput) (UserPage, error) {
	if actor.Validate() != nil {
		return UserPage{}, accessdomain.ErrForbidden
	}
	query, err := NormalizeUserList(input)
	if err != nil {
		return UserPage{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	users, err := s.repo.ListUsers(ctx, actor, query)
	if err != nil {
		return UserPage{}, err
	}
	return UserPageFromRows(users, input.Limit), nil
}

func NormalizeUserList(input UserListInput) (UserListQuery, error) {
	if input.Limit < 1 || input.Limit > 100 || (input.Status != "" && input.Status != domain.StatusActive && input.Status != domain.StatusPending && input.Status != domain.StatusBlocked) {
		return UserListQuery{}, domain.ErrInvalidUserQuery
	}
	query := UserListQuery{Status: input.Status, Limit: input.Limit}
	if input.Email != "" {
		email, err := domain.NewEmail(input.Email)
		if err != nil {
			return UserListQuery{}, err
		}
		query.Email = email.String()
	}
	if input.Before != "" {
		if len(input.Before) > 192 {
			return UserListQuery{}, domain.ErrInvalidUserQuery
		}
		raw, err := base64.RawURLEncoding.DecodeString(input.Before)
		if err != nil {
			return UserListQuery{}, domain.ErrInvalidUserQuery
		}
		stamp, id, ok := strings.Cut(string(raw), "|")
		created, err := time.Parse(time.RFC3339Nano, stamp)
		if !ok || err != nil || !domain.ValidUserID(domain.UserID(id)) || userCursor(created, domain.UserID(id)) != input.Before {
			return UserListQuery{}, domain.ErrInvalidUserQuery
		}
		query.BeforeCreatedAt, query.BeforeID = &created, domain.UserID(id)
	}
	return query, nil
}

// UserPageFromRows consumes at most limit+1 rows from a validated directory query.
func UserPageFromRows(users []UserSummary, limit int) UserPage {
	page := UserPage{Users: users}
	if len(users) > limit {
		page.Users = users[:limit]
		last := page.Users[len(page.Users)-1]
		page.NextCursor = userCursor(last.CreatedAt, last.ID)
	}
	if page.Users == nil {
		page.Users = []UserSummary{}
	}
	return page
}

func userCursor(created time.Time, id domain.UserID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(created.UTC().Format(time.RFC3339Nano) + "|" + string(id)))
}
