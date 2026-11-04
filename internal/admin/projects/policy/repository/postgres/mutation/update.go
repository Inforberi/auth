package mutation

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func ApplyAuthPolicyInTransaction(ctx context.Context, tx pgx.Tx, actor domain.PlatformActor, binding credentials.Binding, command domain.AuthPolicyUpdate, available settingsdomain.PolicyRuntime) (domain.AuthPolicyResult, error) {
	if err := schemapostgres.CheckRuntime(ctx, tx, binding); err != nil {
		return domain.AuthPolicyResult{}, err
	}
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return domain.AuthPolicyResult{}, sqlerrors.Catalog(ctx, err)
	}
	encodedBinding, err := json.Marshal(binding)
	if err != nil {
		return domain.AuthPolicyResult{}, domain.ErrUnavailable
	}
	request, err := json.Marshal(command)
	if err != nil {
		return domain.AuthPolicyResult{}, domain.ErrUnavailable
	}
	if result, found, err := ReadReceipt(ctx, tx, actor, command, encodedBinding, request); found || err != nil {
		return result, err
	}
	before, err := settingspostgres.LockPolicyInTransaction(ctx, tx)
	if err != nil {
		return domain.AuthPolicyResult{}, sqlerrors.Policy(ctx, err)
	}
	// Only the trusted project assembler can supply usable adapters; ENV fallback is forbidden here.
	available.RequireStoredProviders = true
	if err := settingspostgres.CheckPolicyChange(ctx, tx, before, command.ExpectedPolicyVersion, command.Policy, available); err != nil {
		return domain.AuthPolicyResult{}, sqlerrors.Policy(ctx, err)
	}
	after := before
	changed := before.Policy != command.Policy
	if changed {
		after, err = settingspostgres.ApplyPolicyChange(ctx, tx, command.Policy)
		if err != nil {
			return domain.AuthPolicyResult{}, sqlerrors.Catalog(ctx, err)
		}
	}
	if err := writeReceipt(ctx, tx, actor, command, encodedBinding, request, before, after); err != nil {
		return domain.AuthPolicyResult{}, err
	}
	return domain.AuthPolicyResult{Snapshot: after, Changed: changed, ReceiptAdmissionID: actor.AdmissionID}, nil
}
