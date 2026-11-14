package service_test

import (
	"context"
	"testing"

	configuration "github.com/Inforberi/financial-intelligence/internal/auth/settings/configuration/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type sourceRepository struct {
	input configuration.Prepared
	calls int
}

func (r *sourceRepository) StartConfiguration(_ context.Context, p configuration.Prepared) (configuration.Lease, error) {
	r.input = p
	r.calls++
	return nil, nil
}

func TestAPISettingsDoNotValidateOrReseedEnvironment(t *testing.T) {
	r := &sourceRepository{}
	if _, err := configuration.Start(context.Background(), r, configuration.Input{Mode: domain.SourceAPI, SMTPPassword: "bad\x00seed"}, "", nil, nil); err != nil {
		t.Fatal(err)
	}
	if r.calls != 1 || r.input.Mode != domain.SourceAPI || r.input.Policy != (domain.Policy{}) || len(r.input.Fingerprint) != 0 {
		t.Fatal("API accepted ENV settings as policy")
	}
}

func TestInvalidSourceFailsBeforeStorage(t *testing.T) {
	r := &sourceRepository{}
	if _, err := configuration.Start(context.Background(), r, configuration.Input{Mode: "ENV"}, "", nil, nil); err == nil || r.calls != 0 {
		t.Fatal("unknown source reached storage")
	}
}

func TestSourceMetadataAndTrustedContext(t *testing.T) {
	if domain.SourceMode("").Metadata() != (domain.SourceMetadata{Mode: domain.SourceAPI}) {
		t.Fatal("legacy default changed")
	}
	ctx := configuration.WithSourceMode(context.Background(), domain.SourceENV)
	if !configuration.EnvironmentOwned(ctx) || configuration.EnvironmentOwned(context.Background()) {
		t.Fatal("source context leaked")
	}
}
