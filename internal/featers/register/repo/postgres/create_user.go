package register_postgres

import (
	"context"
)

type User struct {
	ID string
}

func (r *RegisterRepo) CreateUser(ctx context.Context, email, password string) (User, error) {

}
