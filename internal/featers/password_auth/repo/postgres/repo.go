package postgres_password

import (
	"github.com/jackc/pgx/v5/pgxpool"
)

type PasswordRepo struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *PasswordRepo {
	return &PasswordRepo{db: db}
}
