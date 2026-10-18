package service

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type readAuthorityStub struct {
	err        error
	actor      operatordomain.Principal
	permission operatordomain.Permission
}

func (a *readAuthorityStub) AuthorizeRead(_ context.Context, actor operatordomain.Principal, permission operatordomain.Permission) error {
	a.actor, a.permission = actor, permission
	return a.err
}

type catalogStub struct {
	reads, lists int
	query        ListQuery
	page         Page
	err          error
}

func (r *catalogStub) Read(context.Context, domain.ID) (domain.Project, error) {
	r.reads++
	return domain.Project{ID: "1c82c477-3a57-4823-8c49-a476550d8a21"}, r.err
}

func (r *catalogStub) List(_ context.Context, q ListQuery) (Page, error) {
	r.lists++
	r.query = q
	return r.page, r.err
}

func TestCatalogReadAuthority(t *testing.T) {
	actor := operatordomain.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}
	for _, failure := range []error{operatordomain.ErrForbidden, operatordomain.ErrUnavailable} {
		repo := &catalogStub{}
		auth := &readAuthorityStub{err: failure}
		svc := New(repo, auth)
		if _, err := svc.List(t.Context(), actor, ListInput{Limit: 50}); !errors.Is(err, failure) {
			t.Fatal(err)
		}
		if _, err := svc.Read(t.Context(), actor, "invalid"); !errors.Is(err, failure) {
			t.Fatal(err)
		}
		if repo.reads != 0 || repo.lists != 0 || auth.actor != actor || auth.permission != operatordomain.ProjectsRead {
			t.Fatal("catalog accessed without current platform read authority")
		}
	}
	repo, auth := &catalogStub{}, &readAuthorityStub{}
	svc := New(repo, auth)
	if _, err := svc.Read(t.Context(), actor, "1c82c477-3a57-4823-8c49-a476550d8a21"); err != nil || repo.reads != 1 {
		t.Fatal("authorized read failed", err)
	}
	auth.err = operatordomain.ErrForbidden
	if _, err := svc.Read(t.Context(), actor, "1c82c477-3a57-4823-8c49-a476550d8a21"); !errors.Is(err, operatordomain.ErrForbidden) || repo.reads != 1 {
		t.Fatal("authority was cached across requests", err)
	}
}

func TestCatalogCursor(t *testing.T) {
	stamp := time.Date(2026, 10, 18, 12, 30, 45, 123456000, time.UTC)
	cursor := Cursor{CreatedAt: stamp, ID: "1c82c477-3a57-4823-8c49-a476550d8a21"}
	encoded := encodeCursor(cursor, domain.Ready)
	repo := &catalogStub{page: Page{Next: &cursor}}
	svc := New(repo, &readAuthorityStub{})
	page, err := svc.List(t.Context(), operatordomain.Principal{}, ListInput{Limit: 1, Phase: domain.Ready})
	if err != nil || page.NextCursor != encoded {
		t.Fatal("missing canonical cursor", err)
	}
	_, err = svc.List(t.Context(), operatordomain.Principal{}, ListInput{Limit: 1, Phase: domain.Ready, Before: encoded})
	if err != nil || repo.query.Before == nil || *repo.query.Before != cursor || repo.query.Limit != 1 || repo.query.Phase != domain.Ready {
		t.Fatal("cursor did not round trip", err)
	}
	for _, bad := range []string{
		encoded + "=", "!", strings.Repeat("a", 257),
		base64.RawURLEncoding.EncodeToString([]byte("2|ready|2026-10-18T12:30:45Z|" + string(cursor.ID))),
		base64.RawURLEncoding.EncodeToString([]byte("1|pending|2026-10-18T12:30:45Z|" + string(cursor.ID))),
		base64.RawURLEncoding.EncodeToString([]byte("1|ready|2026-10-18T12:30:45+00:00|" + string(cursor.ID))),
		base64.RawURLEncoding.EncodeToString([]byte("1|ready|0000-01-01T00:00:00Z|" + string(cursor.ID))),
		base64.RawURLEncoding.EncodeToString([]byte("1|ready|not-a-date|" + string(cursor.ID))),
	} {
		before := repo.lists
		if _, err := svc.List(t.Context(), operatordomain.Principal{}, ListInput{Limit: 1, Phase: domain.Ready, Before: bad}); !errors.Is(err, domain.ErrInvalidPage) || before != repo.lists {
			t.Fatal("malformed or foreign-filter cursor reached storage", err)
		}
	}
}
