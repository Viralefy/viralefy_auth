package domain

import (
	"context"
	"time"
)

// Admin — mesma estrutura do core, copiada para evitar dependência cruzada.
// auth conhece role só pra emitir claim no JWT; RBAC fino fica no core.
type Admin struct {
	ID            string
	Email         string
	PasswordHash  string
	Name          string
	Role          string
	RequiresTwoFA bool
	CreatedAt     time.Time
}

type AdminRepository interface {
	GetByID(ctx context.Context, id string) (*Admin, error)
	GetByEmail(ctx context.Context, email string) (*Admin, error)
	UpdatePasswordHash(ctx context.Context, id, newHash string) error
}
