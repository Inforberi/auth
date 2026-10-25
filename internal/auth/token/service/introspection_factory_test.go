package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestIntrospectionBindingsShareAdmissionAndClientOwnership(t *testing.T) {
	service, _, _, secret, sign := introspectionFixture(t)
	factory := &IntrospectionFactory{template: *service}
	factory.template.repo = nil
	firstRepo, secondRepo := &introspectionRepo{}, &introspectionRepo{}
	first, err := factory.Bind(firstRepo)
	require.NoError(t, err)
	second, err := factory.Bind(secondRepo)
	require.NoError(t, err)
	require.Nil(t, factory.template.repo)
	require.Same(t, firstRepo, first.repo)
	require.Same(t, secondRepo, second.repo)
	client, ok := factory.Authenticate("orders-api", secret)
	require.True(t, ok)
	result, err := first.Inspect(t.Context(), client, sign("orders", "orders.read"))
	require.NoError(t, err)
	require.True(t, result.Active)
	result, err = second.Inspect(t.Context(), client, sign("orders", "orders.read"))
	require.NoError(t, err)
	require.True(t, result.Active)
	require.Equal(t, 1, firstRepo.calls)
	require.Equal(t, 1, secondRepo.calls)
	for range cap(first.admission) {
		first.admission <- struct{}{}
	}
	result, err = second.Inspect(t.Context(), client, sign("orders", "orders.read"))
	require.ErrorIs(t, err, authjwt.ErrBusy)
	require.False(t, result.Active)
	for range cap(first.admission) {
		<-first.admission
	}
	other, _, _, otherSecret, _ := introspectionFixture(t)
	foreign, ok := other.Authenticate("orders-api", otherSecret)
	require.True(t, ok)
	result, err = second.Inspect(t.Context(), foreign, sign("orders", "orders.read"))
	require.ErrorIs(t, err, domain.ErrForbidden)
	require.False(t, result.Active)
	require.Equal(t, 1, secondRepo.calls)
	_, err = factory.Bind(nil)
	require.ErrorIs(t, err, authjwt.ErrConfiguration)
}
