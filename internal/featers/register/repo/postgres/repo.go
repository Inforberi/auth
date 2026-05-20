package register_postgres

import "github.com/jackc/pgx/v5/pgxpool"

type RegisterRepo struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *RegisterRepo {
	return &RegisterRepo{db: db}
}
