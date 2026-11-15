package domain

type Rename struct {
	ProjectID       ID
	OperationID     ID
	ExpectedVersion int64
	Name            string
	Reason          string
}

func (r Rename) Normalize() (Rename, error) {
	if !ValidID(r.ProjectID) || !ValidID(r.OperationID) || r.ExpectedVersion < 1 || !validReason(r.Reason) {
		return Rename{}, ErrInvalidProject
	}
	name, err := NormalizeName(r.Name)
	r.Name = name
	return r, err
}

type NameReceipt struct {
	Name     string
	Version  int64
	Replayed bool
}
