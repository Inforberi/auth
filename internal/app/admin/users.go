package admin

import (
	"context"

	"go.uber.org/zap"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	directorypostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/directory/repository/postgres"
	directoryservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/directory/service"
	directoryhttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/directory/transport/http"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/transport/http/projects"
)

func ProjectUsers(runtime *projectruntime.Registry, repo *projectpostgres.Repository, log *zap.Logger, projectHTTP *projectbrowser.ProjectHTTP) *directoryhttp.UserHandler {
	if runtime == nil {
		return nil
	}
	backend := directorypostgres.NewRuntimeUsers(repo, runtime)
	return directoryhttp.NewUsers(directoryservice.NewUsers(backend), log).WithLifecycle(func(ctx context.Context, actor operatordomain.Principal, target projectdomain.DirectoryTarget, user accountdomain.UserID, input directoryhttp.LifecycleCommand) (directoryhttp.LifecycleReceipt, error) {
		var receipt directoryhttp.LifecycleReceipt
		if !projectdomain.ValidID(input.OperationID) || !accountdomain.ValidUserID(user) || input.AuthVersion < 1 ||
			(input.Action != "initial_email" && input.Email != "") {
			return receipt, projectdomain.ErrInvalidProject
		}
		command := accountpostgres.PlatformLifecycle{OperationID: string(input.OperationID), UserID: user, Action: input.Action, ExpectedVersion: input.AuthVersion}
		switch input.Action {
		case "initial_email":
			email, err := accountdomain.NewEmail(input.Email)
			if err != nil {
				return receipt, err
			}
			command.Email = email
		case "temporary_password":
			selected, err := repo.ResolveProjectTarget(ctx, actor, target, operatordomain.UsersManage)
			if err != nil {
				return receipt, err
			}
			command.Temporary, err = projectHTTP.PrepareTemporaryReissue(ctx, selected.Key, selected.Origin, actor.UserID)
			if err != nil {
				return receipt, err
			}
			command.TemporaryResult = &passwordprovisioning.TemporaryIssueResult{}
		}
		version, err := repo.ChangeProjectUser(ctx, actor, target, runtime, command)
		if err != nil {
			return receipt, err
		}
		receipt.AuthVersion = version
		if result := command.TemporaryResult; result != nil && !result.Reused {
			command.Temporary.Reveal(result)
			receipt.TemporaryPassword, receipt.ExpiresAt = result.Password, &result.ExpiresAt
		}
		return receipt, nil
	}).WithCreation(func(ctx context.Context, actor operatordomain.Principal, target projectdomain.DirectoryTarget, input directoryhttp.CreateUserCommand) (directoryhttp.CreateUserReceipt, error) {
		var receipt directoryhttp.CreateUserReceipt
		if !projectdomain.ValidID(input.OperationID) || input.InvitationEmail != "" && input.TemporaryPasswordEmail != "" {
			return receipt, projectdomain.ErrInvalidProject
		}
		command := accountpostgres.PlatformCreation{OperationID: string(input.OperationID)}
		if input.InvitationEmail != "" || input.TemporaryPasswordEmail != "" {
			selected, err := repo.ResolveProjectTarget(ctx, actor, target, operatordomain.UsersManage)
			if err != nil {
				return receipt, err
			}
			if input.InvitationEmail != "" {
				command.Invitation, err = projectHTTP.PrepareInvitation(ctx, selected.Key, selected.Origin, actor.UserID, input.InvitationEmail)
			} else {
				command.Temporary, err = projectHTTP.PrepareTemporaryPassword(ctx, selected.Key, selected.Origin, actor.UserID, input.TemporaryPasswordEmail)
				command.TemporaryResult = &passwordprovisioning.TemporaryIssueResult{}
			}
			if err != nil {
				return receipt, err
			}
		}
		user, err := repo.CreateProjectUser(ctx, actor, target, runtime, command)
		if err != nil {
			return receipt, err
		}
		receipt.UserID = user
		if result := command.TemporaryResult; result != nil && !result.Reused {
			command.Temporary.Reveal(result)
			receipt.TemporaryPassword, receipt.ExpiresAt = result.Password, &result.ExpiresAt
		}
		return receipt, nil
	})
}
