package domain

import "errors"

type SourceMode string

const (
	SourceAPI SourceMode = "api"
	SourceENV SourceMode = "env"
)

var (
	ErrSourceReadOnly = errors.New("settings source is read-only")
	ErrSourceConflict = errors.New("settings source conflicts with this deployment")
	ErrSourceAdoption = errors.New("existing settings require explicit source adoption")
)

func (m SourceMode) Effective() SourceMode {
	if m == "" {
		return SourceAPI
	}
	return m
}

func (m SourceMode) Validate() error {
	if m.Effective() != SourceAPI && m != SourceENV {
		return ErrSourceConflict
	}
	return nil
}

type SourceMetadata struct {
	Mode     SourceMode `json:"mode" swaggertype:"string" enums:"api,env"`
	ReadOnly bool       `json:"readOnly"`
}

func (m SourceMode) Metadata() SourceMetadata {
	return SourceMetadata{Mode: m.Effective(), ReadOnly: m == SourceENV}
}
