package preparation

import (
	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
)

type Connections struct {
	Catalog, Storage *pgx.ConnConfig
	Codec            *credentials.Codec
}
