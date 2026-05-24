package session_postgres

import "github.com/jackc/pgx/v5/pgxpool"

type SessionRepo struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *SessionRepo {
	return &SessionRepo{db: db}
}
