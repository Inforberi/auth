package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	directoryservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/directory/service"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

type userDirectoryStub struct {
	query accountservice.UserListQuery
	calls int
	users []accountservice.UserSummary
	err   error
}

func (s *userDirectoryStub) ListProjectUsers(_ context.Context, _ operatordomain.Principal, _ domain.DirectoryTarget, query accountservice.UserListQuery) ([]accountservice.UserSummary, error) {
	s.calls++
	s.query = query
	return s.users, s.err
}

func (s *userDirectoryStub) ReadProjectUser(context.Context, operatordomain.Principal, domain.DirectoryTarget, accountdomain.UserID) (accountservice.UserDetail, error) {
	s.calls++
	return accountservice.UserDetail{}, s.err
}

func TestPlatformUserDirectoryUsesAccountQueryContract(t *testing.T) {
	target := domain.DirectoryTarget{ProjectID: "11111111-1111-4111-8111-111111111111", ExpectedVersion: 1, ExpectedGeneration: 2}
	for _, input := range []accountservice.UserListInput{
		{Limit: 101}, {Limit: 0}, {Limit: 50, Before: "forged"}, {Limit: 50, Email: "invalid"}, {Limit: 50, Status: "deleted"},
	} {
		repo := &userDirectoryStub{}
		_, err := directoryservice.NewUsers(repo).ListProjectUsers(t.Context(), operatordomain.Principal{}, target, input)
		require.Error(t, err)
		require.Zero(t, repo.calls)
	}
	repo := &userDirectoryStub{users: []accountservice.UserSummary{
		{ID: "11111111-1111-4111-8111-111111111111", CreatedAt: time.Now()},
		{ID: "22222222-2222-4222-8222-222222222222", CreatedAt: time.Now().Add(-time.Second)},
	}}
	s := directoryservice.NewUsers(repo)
	page, err := s.ListProjectUsers(t.Context(), operatordomain.Principal{}, target, accountservice.UserListInput{Limit: 1, Email: "PERSON@example.test"})
	require.NoError(t, err)
	require.Equal(t, "person@example.test", repo.query.Email)
	require.Len(t, page.Users, 1)
	require.NotEmpty(t, page.NextCursor)
	_, err = s.ListProjectUsers(t.Context(), operatordomain.Principal{}, target, accountservice.UserListInput{Limit: 1, Before: page.NextCursor})
	require.NoError(t, err)
	require.Equal(t, page.Users[0].ID, repo.query.BeforeID)
	repo.err = operatordomain.ErrForbidden
	page, err = s.ListProjectUsers(t.Context(), operatordomain.Principal{}, target, accountservice.UserListInput{Limit: 1})
	require.ErrorIs(t, err, repo.err)
	require.Empty(t, page.Users)
	before := repo.calls
	_, err = s.ReadProjectUser(t.Context(), operatordomain.Principal{}, target, "invalid-id")
	require.Error(t, err)
	require.Equal(t, before, repo.calls)
}
