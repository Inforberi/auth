package domain

type PreparationOperation struct {
	OperationID ID     `json:"operationId" swaggertype:"string"`
	ProjectID   ID     `json:"projectId" swaggertype:"string"`
	Version     int64  `json:"expectedVersion"`
	Generation  int64  `json:"expectedGeneration"`
	Stage       string `json:"stage"`
	Phase       Phase  `json:"phase" swaggertype:"string"`
}
