package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/service"
)

func TestCatalogBoundsBeforeQuery(t *testing.T) {
	repo := New(nil)
	if _, err := repo.Read(t.Context(), "invalid"); !errors.Is(err, domain.ErrInvalidProject) {
		t.Fatal("invalid ID reached storage")
	}
	if _, err := repo.Resolve(t.Context(), "https://unknown.example/path"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("noncanonical origin reached storage")
	}
	for _, q := range []service.ListQuery{
		{Limit: 0},
		{Limit: -1},
		{Limit: 101},
		{Limit: 1, Phase: "unknown"},
		{Limit: 1, Before: &service.Cursor{ID: "1c82c477-3a57-4823-8c49-a476550d8a21"}},
		{Limit: 1, Before: &service.Cursor{CreatedAt: time.Now(), ID: "invalid"}},
	} {
		if _, err := repo.List(t.Context(), q); !errors.Is(err, domain.ErrInvalidPage) {
			t.Fatal("unbounded/invalid page reached storage")
		}
	}
}

func TestCatalogErrorsAreSafe(t *testing.T) {
	if catalogError(t.Context(), nil) != nil || !errors.Is(catalogError(t.Context(), pgx.ErrNoRows), domain.ErrNotFound) {
		t.Fatal("incorrect no-row mapping")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := catalogError(ctx, errors.New("postgres://private-user:private-password@private-host/database"))
	if !errors.Is(err, domain.ErrUnavailable) || !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "private-") {
		t.Fatal("catalog error leaked driver details or lost cancellation")
	}
}
