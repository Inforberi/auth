package domain

import (
	"errors"
	"time"
)

type (
	ID           string
	DesiredState string
	Phase        string
)

const (
	Enabled   DesiredState = "enabled"
	Suspended DesiredState = "suspended"

	Pending      Phase = "pending"
	Provisioning Phase = "provisioning"
	Failed       Phase = "failed"
	Ready        Phase = "ready"
)

var (
	ErrInvalidProject = errors.New("invalid project")
	ErrNotFound       = errors.New("project not found")
	ErrUnavailable    = errors.New("project catalog unavailable")
)

type Project struct {
	ID           ID
	Slug         string
	Name         string
	Origin       string
	DesiredState DesiredState
	Phase        Phase
	Version      int64
	Generation   int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (p Project) AdmitsRequests() bool {
	return p.DesiredState == Enabled && p.Phase == Ready
}

func (p Phase) Valid() bool {
	return p == Pending || p == Provisioning || p == Failed || p == Ready
}
