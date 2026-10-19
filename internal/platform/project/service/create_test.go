package service

import (
	"errors"
	"testing"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func TestCreationUsesMutationPort(t *testing.T) {
	repo := &catalogStub{}
	auth := &readAuthorityStub{err: errors.New("read must not authorize creation")}
	actor := operatordomain.Principal{UserID: "11111111-1111-4111-8111-111111111111"}
	input := CreateInput{OperationID: "22222222-2222-4222-8222-222222222222", Slug: "shop", Name: "Shop", Reason: "incident"}
	result, err := New(repo, auth).Create(t.Context(), actor, input)
	if err != nil || result.Project.Slug != "shop" || repo.actor != actor || repo.creation != (domain.Create{OperationID: input.OperationID, Slug: input.Slug, Name: input.Name, Reason: input.Reason}) || auth.permission != "" {
		t.Fatal("incorrect creation port/authority mapping", err)
	}
}
