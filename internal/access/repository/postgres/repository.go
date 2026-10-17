package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/access/service"
)

type Repository struct {
	db       *pgxpool.Pool
	mfaReady bool
}

func New(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func NewWithMFA(db *pgxpool.Pool, ready bool) *Repository {
	return &Repository{db: db, mfaReady: ready}
}

var _ service.Repository = (*Repository)(nil)
