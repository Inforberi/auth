package register_postgres

import (
	"context"

	register_service "github.com/Inforberi/financial-intelligence/internal/featers/register/service"
)

type User struct {
	ID string
}

func (r *RegisterRepo) CreateUser(ctx context.Context, input register_service.Input) (User, error) {

}
