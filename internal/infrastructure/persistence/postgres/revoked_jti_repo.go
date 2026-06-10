package postgres

import (
	"context"

	"github.com/Viralefy/viralefy_auth/internal/domain"
)

type RevokedJTIRepo struct{ db *DB }

func NewRevokedJTIRepo(db *DB) *RevokedJTIRepo { return &RevokedJTIRepo{db: db} }

// Add insere uma row no hot-set. Notifica o canal `revoked_jtis_inserted`
// pra dispatcher pickar via LISTEN/NOTIFY se quiser baixo lag.
func (r *RevokedJTIRepo) Add(ctx context.Context, x domain.RevokedJTI) error {
	tx, err := r.db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `
		INSERT INTO revoked_jtis (jti, expires_at, revoked_reason, revoked_by_admin_id, revoked_by_user_id)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5)
		ON CONFLICT (jti) DO NOTHING`,
		x.JTI, x.ExpiresAt, x.Reason, x.ByAdminID, x.ByUserID,
	); err != nil {
		return err
	}
	// Push pra dispatcher. Payload mínimo (só o jti). Quem ouve faz lookup
	// se quiser metadata. NOTIFY é fire-and-forget — falha de ouvinte
	// não bloqueia a revogação.
	if _, err := tx.Exec(ctx, `SELECT pg_notify('revoked_jtis_inserted', $1)`, x.JTI); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *RevokedJTIRepo) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var exists bool
	err := r.db.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM revoked_jtis WHERE jti=$1 AND expires_at > NOW())`,
		jti,
	).Scan(&exists)
	return exists, err
}

func (r *RevokedJTIRepo) ListActive(ctx context.Context) ([]domain.RevokedJTI, error) {
	rows, err := r.db.pool.Query(ctx, `
		SELECT jti, expires_at, revoked_at, COALESCE(revoked_reason,''),
			revoked_by_admin_id, revoked_by_user_id
		FROM revoked_jtis WHERE expires_at > NOW()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.RevokedJTI{}
	for rows.Next() {
		var x domain.RevokedJTI
		if err := rows.Scan(&x.JTI, &x.ExpiresAt, &x.RevokedAt, &x.Reason,
			&x.ByAdminID, &x.ByUserID); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
