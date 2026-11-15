package domain

type DeletionRequest struct {
	Target           DirectoryTarget
	OperationID      ID
	ConfirmProject   ID
	ConfirmLoss      bool
	AcknowledgeUsers bool
}

type DeletionOperation struct {
	ProjectID   ID     `json:"projectId" swaggertype:"string"`
	OperationID ID     `json:"operationId" swaggertype:"string"`
	Stage       string `json:"stage"`
}

func (c DeletionRequest) Validate() error {
	if c.Target.Validate() != nil || !ValidID(c.OperationID) || c.ConfirmProject != c.Target.ProjectID || !c.ConfirmLoss {
		return ErrInvalidProject
	}
	return nil
}
