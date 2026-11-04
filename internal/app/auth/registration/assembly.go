package registration

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
)

func Assemble(pool *pgxpool.Pool, service *accountemail.Verification, repo *accountpostgres.Repository) *passwordpostgres.PasswordRepo {
	return passwordpostgres.NewWithRegistration(pool, func(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, emailID accountdomain.AddressID, email string) error {
		prepared, err := service.PrepareVerification(email)
		if err != nil {
			return err
		}
		return repo.QueueInTransaction(ctx, tx, user, emailID, prepared)
	})
}
