package register_service

import (
	"context"
	"fmt"
)

type Input struct {
	email    string
	password string
}

type Result struct {
	UserID string
}

func (r *RegisterService) RegisterByEmail(ctx context.Context, input Input) (*Result, error) {
	found, err := r.repo.ExistsByEmail(ctx, input.email)
	if err != nil {
		return &Result{}, fmt.Errorf("check email exists %w", err)
	}
	if found {
		return &Result{}, fmt.Errorf("")
	}

	
}
