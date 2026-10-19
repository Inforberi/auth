package domain

import (
	"strings"
	"time"
)

type PreparationRequest struct {
	ProjectID          ID
	OperationID        ID
	ExpectedVersion    int64
	ExpectedGeneration int64
}

type PreparationReservation struct {
	ProjectID     ID
	ReservationID ID
	StorageTarget string
	OperationID   ID
	Version       int64
	Generation    int64
	CreatedAt     time.Time
}

func (r PreparationReservation) ResourceNames() (database, owner string, err error) {
	if !ValidID(r.ProjectID) || !ValidID(r.ReservationID) {
		return "", "", ErrInvalidProject
	}
	key := strings.ReplaceAll(string(r.ProjectID), "-", "")
	return "authp_" + key, "autho_" + key, nil
}
