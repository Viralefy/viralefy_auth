package domain

import (
	"context"
	"time"
)

// User é o que auth precisa saber sobre a tabela `users`. Subset dos
// campos do core — auth NÃO toca em profile, créditos, etc.
type User struct {
	ID           string
	Email        string
	Name         string
	PasswordHash string
	Phone        string
	Telegram     string
	CreatedAt    time.Time
	DeletedAt    *time.Time
}

type UserRepository interface {
	GetByID(ctx context.Context, id string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Create(ctx context.Context, u User) error
	UpdatePasswordHash(ctx context.Context, id, newHash string) error
}
