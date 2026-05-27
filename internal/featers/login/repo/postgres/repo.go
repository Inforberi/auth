package login_postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"
)

type LoginRepo struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *LoginRepo {
	return &LoginRepo{db: db}
}
