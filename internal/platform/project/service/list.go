package service

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type Cursor struct {
	CreatedAt time.Time
	ID        domain.ID
}

type ListQuery struct {
	Limit  int
	Before *Cursor
	Phase  domain.Phase
}

type Page struct {
	Projects []domain.Project
	Next     *Cursor
}

type ListInput struct {
	Limit  int
	Before string
	Phase  domain.Phase
}

type ListResult struct {
	Projects   []domain.Project
	NextCursor string
}

func (s *Catalog) List(ctx context.Context, actor operatordomain.Principal, input ListInput) (ListResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.authority.AuthorizeRead(ctx, actor, operatordomain.ProjectsRead); err != nil {
		return ListResult{}, err
	}
	before, err := decodeCursor(input.Before, input.Phase)
	if err != nil {
		return ListResult{}, err
	}
	page, err := s.repo.List(ctx, ListQuery{Limit: input.Limit, Phase: input.Phase, Before: before})
	if err != nil {
		return ListResult{}, err
	}
	result := ListResult{Projects: page.Projects}
	if page.Next != nil {
		result.NextCursor = encodeCursor(*page.Next, input.Phase)
	}
	return result, nil
}

func encodeCursor(cursor Cursor, phase domain.Phase) string {
	return base64.RawURLEncoding.EncodeToString([]byte("1|" + string(phase) + "|" + cursor.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + string(cursor.ID)))
}

func decodeCursor(value string, phase domain.Phase) (*Cursor, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > 256 {
		return nil, domain.ErrInvalidPage
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, domain.ErrInvalidPage
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 || parts[0] != "1" || parts[1] != string(phase) {
		return nil, domain.ErrInvalidPage
	}
	created, err := time.Parse(time.RFC3339Nano, parts[2])
	if err != nil || created.Year() < 1 || created.Year() > 9999 {
		return nil, domain.ErrInvalidPage
	}
	cursor := &Cursor{CreatedAt: created, ID: domain.ID(parts[3])}
	if encodeCursor(*cursor, phase) != value {
		return nil, domain.ErrInvalidPage
	}
	return cursor, nil
}
