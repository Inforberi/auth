package service

import "time"

// CreatedSession is the result of issuance; RawToken is never stored in the ledger.
type CreatedSession struct {
	RawToken  string
	ExpiresAt time.Time
}
