package service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/audit/domain"
)

// Recorder failure must abort a security-critical write unless the event has
// already been committed in the same SQL transaction through an outbox.
type Recorder interface {
	Record(context.Context, domain.Event) error
}
