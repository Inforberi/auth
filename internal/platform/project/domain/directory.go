package domain

type DirectoryTarget struct {
	ProjectID                           ID
	ExpectedVersion, ExpectedGeneration int64
}

func (t DirectoryTarget) Validate() error {
	if !ValidID(t.ProjectID) || t.ExpectedVersion < 1 || t.ExpectedGeneration < 1 {
		return ErrInvalidProject
	}
	return nil
}
