package postgres

import (
	"context"
	"errors"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/jackc/pgx/v5"
)

type PasswordResetRepo struct{ db *DB }

func NewPasswordResetRepo(db *DB) *PasswordResetRepo { return &PasswordResetRepo{db: db} }

func (r *PasswordResetRepo) Create(ctx context.Context, p domain.PasswordReset) error {
	_, err := r.db.pool.Exec(ctx, `
		INSERT INTO password_resets (id, token_hash, user_id, admin_id, expires_at,
			requested_ip, requested_user_agent)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''))`,
		p.ID, p.TokenHash, p.UserID, p.AdminID, p.ExpiresAt,
		p.RequestedIP, p.RequestedUserAgent)
	return err
}

func (r *PasswordResetRepo) GetByHash(ctx context.Context, hash string) (*domain.PasswordReset, error) {
	row := r.db.pool.QueryRow(ctx, `
		SELECT id, token_hash, user_id, admin_id, requested_at, expires_at, used_at,
			COALESCE(requested_ip, ''), COALESCE(requested_user_agent, '')
		FROM password_resets WHERE token_hash=$1`, hash)
	var p domain.PasswordReset
	err := row.Scan(&p.ID, &p.TokenHash, &p.UserID, &p.AdminID,
		&p.RequestedAt, &p.ExpiresAt, &p.UsedAt,
		&p.RequestedIP, &p.RequestedUserAgent)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *PasswordResetRepo) MarkUsed(ctx context.Context, id string) error {
	tag, err := r.db.pool.Exec(ctx,
		`UPDATE password_resets SET used_at=NOW() WHERE id=$1 AND used_at IS NULL`,
		id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
