package postgres

import (
	"context"
	"errors"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/jackc/pgx/v5"
)

type RefreshTokenRepo struct{ db *DB }

func NewRefreshTokenRepo(db *DB) *RefreshTokenRepo { return &RefreshTokenRepo{db: db} }

const refreshCols = `id, token_hash, user_id, admin_id, issued_at, expires_at, revoked_at, replaced_by_id,
	COALESCE(issue_ip, '') AS issue_ip, COALESCE(issue_user_agent, '') AS issue_user_agent`

func (r *RefreshTokenRepo) Create(ctx context.Context, t domain.RefreshToken) error {
	_, err := r.db.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, token_hash, user_id, admin_id,
			issued_at, expires_at, issue_ip, issue_user_agent)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,''))`,
		t.ID, t.TokenHash, t.UserID, t.AdminID,
		t.IssuedAt, t.ExpiresAt, t.IssueIP, t.IssueUserAgent)
	return err
}

func (r *RefreshTokenRepo) GetByHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	row := r.db.pool.QueryRow(ctx, `SELECT `+refreshCols+` FROM refresh_tokens WHERE token_hash=$1`, hash)
	var t domain.RefreshToken
	err := row.Scan(&t.ID, &t.TokenHash, &t.UserID, &t.AdminID,
		&t.IssuedAt, &t.ExpiresAt, &t.RevokedAt, &t.ReplacedByID,
		&t.IssueIP, &t.IssueUserAgent)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Revoke marca o token como revogado + replaced_by. replacedBy pode ser vazio
// pra logout (não há substituto).
func (r *RefreshTokenRepo) Revoke(ctx context.Context, id, replacedBy string) error {
	var replaced *string
	if replacedBy != "" {
		replaced = &replacedBy
	}
	tag, err := r.db.pool.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW(), replaced_by_id = $2
		WHERE id=$1 AND revoked_at IS NULL`,
		id, replaced)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// RevokeBySubject força logout total de um subject (todos os refresh tokens
// ativos viram revogados). Usado em incidente, password reset, mudança de role.
func (r *RefreshTokenRepo) RevokeBySubject(ctx context.Context, subj domain.Subject) error {
	var col, val string
	if subj.Kind == domain.SubjectAdmin {
		col, val = "admin_id", subj.AdminID
	} else {
		col, val = "user_id", subj.UserID
	}
	_, err := r.db.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE `+col+`=$1 AND revoked_at IS NULL`,
		val)
	return err
}
