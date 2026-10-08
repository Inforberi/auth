package domain

import "time"

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
