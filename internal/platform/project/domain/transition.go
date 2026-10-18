package domain

import (
	"errors"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

type (
	Action    string
	ActorKind string
)

const (
	BeginPreparation  Action = "begin_preparation"
	FailPreparation   Action = "fail_preparation"
	FinishPreparation Action = "finish_preparation"
	RetryPreparation  Action = "retry"
	Suspend           Action = "suspend"
	Resume            Action = "resume"

	OperatorActor    ActorKind = "operator"
	ProvisionerActor ActorKind = "provisioner"
)

var (
	ErrConflict          = errors.New("project version or operation conflict")
	ErrInvalidTransition = errors.New("invalid project transition")
)

type Transition struct {
	ProjectID          ID
	OperationID        ID
	ExpectedVersion    int64
	ExpectedGeneration int64
	Action             Action
	ActorKind          ActorKind
	ActorID            ID
	Reason             string
}

type TransitionReceipt struct {
	ProjectID    ID
	DesiredState DesiredState
	Phase        Phase
	Version      int64
	Generation   int64
	Replayed     bool
}

func (c Transition) Validate() error {
	if !ValidID(c.ProjectID) || !ValidID(c.OperationID) || !ValidID(c.ActorID) || c.ExpectedVersion < 1 || c.ExpectedGeneration < 1 ||
		len(c.Reason) == 0 || len(c.Reason) > 500 || !utf8.ValidString(c.Reason) ||
		strings.TrimSpace(c.Reason) != c.Reason || strings.ContainsFunc(c.Reason, unicode.IsControl) {
		return ErrInvalidProject
	}
	switch c.Action {
	case Suspend, Resume, RetryPreparation:
		if c.ActorKind == OperatorActor {
			return nil
		}
	case BeginPreparation, FailPreparation, FinishPreparation:
		if c.ActorKind == ProvisionerActor {
			return nil
		}
	}
	return ErrInvalidProject
}

// Next changes catalog lifecycle only; health probes cannot supply an Action.
func (p Project) Next(action Action) (Project, error) {
	if !p.DesiredState.Valid() || !p.Phase.Valid() {
		return Project{}, ErrInvalidTransition
	}
	if !canAdvance(p.Version) || !canAdvance(p.Generation) {
		return Project{}, ErrConflict
	}
	switch {
	case action == Suspend && p.DesiredState == Enabled:
		p.DesiredState = Suspended
	case action == Resume && p.DesiredState == Suspended:
		p.DesiredState = Enabled
	case action == BeginPreparation && p.DesiredState == Enabled && p.Phase == Pending:
		p.Phase = Provisioning
	case action == FailPreparation && p.Phase == Provisioning:
		p.Phase = Failed
	case action == FinishPreparation && p.Phase == Provisioning:
		p.Phase = Ready
	case action == RetryPreparation && p.DesiredState == Enabled && p.Phase == Failed:
		p.Phase = Pending
	default:
		return Project{}, ErrInvalidTransition
	}
	p.Version++
	p.Generation++
	return p, nil
}

func canAdvance(version int64) bool { return version > 0 && version < math.MaxInt64 }
