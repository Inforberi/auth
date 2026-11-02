package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func (a *AdmittedAuthPolicy) Execute(ctx context.Context, project ProjectDatabase, available settingsdomain.PolicyRuntime) (domain.AuthPolicyResult, error) {
	if a == nil || a.used == nil || !a.actor.Valid() || !time.Now().Before(a.until) {
		return domain.AuthPolicyResult{}, domain.ErrAdmissionExpired
	}
	var result domain.AuthPolicyResult
	err := executeProjectTransaction(ctx, project, a.until, a.used, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = a.changePolicy(ctx, tx, available)
		return err
	})
	if err != nil {
		return domain.AuthPolicyResult{}, err
	}
	return result, nil
}

func (a *AdmittedAuthPolicy) changePolicy(ctx context.Context, tx pgx.Tx, available settingsdomain.PolicyRuntime) (domain.AuthPolicyResult, error) {
	if err := schemapostgres.CheckRuntime(ctx, tx, a.binding); err != nil {
		return domain.AuthPolicyResult{}, err
	}
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return domain.AuthPolicyResult{}, sqlerrors.Catalog(ctx, err)
	}
	binding, err := json.Marshal(a.binding)
	if err != nil {
		return domain.AuthPolicyResult{}, domain.ErrUnavailable
	}
	request, err := json.Marshal(a.command)
	if err != nil {
		return domain.AuthPolicyResult{}, domain.ErrUnavailable
	}
	if result, found, err := readPolicyReceipt(ctx, tx, a.actor, a.command, binding, request); found || err != nil {
		return result, err
	}
	before, err := settingspostgres.LockPolicyInTransaction(ctx, tx)
	if err != nil {
		return domain.AuthPolicyResult{}, sqlerrors.Policy(ctx, err)
	}
	// Only the trusted project assembler can supply usable adapters; ENV fallback is forbidden here.
	available.RequireStoredProviders = true
	if err := settingspostgres.CheckPolicyChange(ctx, tx, before, a.command.ExpectedPolicyVersion, a.command.Policy, available); err != nil {
		return domain.AuthPolicyResult{}, sqlerrors.Policy(ctx, err)
	}
	after := before
	changed := before.Policy != a.command.Policy
	if changed {
		after, err = settingspostgres.ApplyPolicyChange(ctx, tx, a.command.Policy)
		if err != nil {
			return domain.AuthPolicyResult{}, sqlerrors.Catalog(ctx, err)
		}
	}
	if err := writePolicyReceipt(ctx, tx, a.actor, a.command, binding, request, before, after); err != nil {
		return domain.AuthPolicyResult{}, err
	}
	return domain.AuthPolicyResult{Snapshot: after, Changed: changed, ReceiptAdmissionID: a.actor.AdmissionID}, nil
}

func (a *AdmittedAuthPolicy) ExecuteWithRuntime(ctx context.Context, registry *projectruntime.Registry, available settingsdomain.PolicyRuntime) (domain.AuthPolicyResult, error) {
	if a == nil || registry == nil {
		return domain.AuthPolicyResult{}, domain.ErrConflict
	}
	key := projectruntime.Key{Binding: a.binding, Version: a.command.ExpectedVersion, Generation: a.command.ExpectedGeneration}
	return withProjectRuntime(ctx, registry, key, a.until, func(ctx context.Context, db projectruntime.Database) (domain.AuthPolicyResult, error) {
		return a.Execute(ctx, db, available)
	})
}
