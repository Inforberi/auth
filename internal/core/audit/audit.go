// Package audit defines the port for durable security events. Access logs are
// not a durable audit sink. Future sensitive use cases must implement this port.
package audit

import (
	"context"
	"time"
)

// Event contains identifiers and classifications only, never credentials or
// arbitrary HTTP bodies. A failing Record must abort a security-critical write
// unless its event has already been committed in a transactional outbox.
type Event struct {
	ID         string
	ActorID    string
	ScopeID    string
	Action     string
	TargetID   string
	Result     string
	RequestID  string
	OccurredAt time.Time
}
type Recorder interface {
	Record(context.Context, Event) error
}
