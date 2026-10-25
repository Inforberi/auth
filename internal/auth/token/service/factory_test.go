package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestFactoryBindingsShareAdmissionWithoutSharingRepository(t *testing.T) {
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "orders.read", Name: "Read orders"}})
	require.NoError(t, err)
	factory, err := NewFactory(&exchangeSigner{}, &exchangeLimiter{}, tokengenerate.New(), Config{AccessTTL: time.Minute, Resources: []Resource{{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read"}}}}, catalog)
	require.NoError(t, err)
	firstRepo, secondRepo := &exchangeRepo{}, &exchangeRepo{}
	first, err := factory.Bind(firstRepo)
	require.NoError(t, err)
	second, err := factory.Bind(secondRepo)
	require.NoError(t, err)
	require.Same(t, firstRepo, first.repo)
	require.Same(t, secondRepo, second.repo)
	require.Nil(t, factory.template.repo)
	for range cap(first.admission) {
		first.admission <- struct{}{}
	}
	select {
	case second.admission <- struct{}{}:
		t.Fatal("binding reset shared admission")
	default:
	}
	for range cap(first.admission) {
		<-first.admission
	}
	_, err = factory.Bind(nil)
	require.ErrorIs(t, err, authjwt.ErrConfiguration)
}
