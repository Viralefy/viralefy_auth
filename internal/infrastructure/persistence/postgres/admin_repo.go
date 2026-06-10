package postgres

import (
	"context"
	"errors"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/jackc/pgx/v5"
)

type AdminRepo struct{ db *DB }

func NewAdminRepo(db *DB) *AdminRepo { return &AdminRepo{db: db} }

const adminCols = `id, email, password_hash, name, role,
	COALESCE(requires_2fa, TRUE) AS requires_2fa,
	created_at`

func (r *AdminRepo) GetByID(ctx context.Context, id string) (*domain.Admin, error) {
	row := r.db.pool.QueryRow(ctx, `SELECT `+adminCols+` FROM admins WHERE id=$1`, id)
	return scanAdmin(row)
}

func (r *AdminRepo) GetByEmail(ctx context.Context, email string) (*domain.Admin, error) {
	row := r.db.pool.QueryRow(ctx, `SELECT `+adminCols+` FROM admins WHERE email=$1`, email)
	return scanAdmin(row)
}

func (r *AdminRepo) UpdatePasswordHash(ctx context.Context, id, newHash string) error {
	tag, err := r.db.pool.Exec(ctx,
		`UPDATE admins SET password_hash=$2 WHERE id=$1`, id, newHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func scanAdmin(row pgx.Row) (*domain.Admin, error) {
	var a domain.Admin
	err := row.Scan(&a.ID, &a.Email, &a.PasswordHash, &a.Name, &a.Role, &a.RequiresTwoFA, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}
