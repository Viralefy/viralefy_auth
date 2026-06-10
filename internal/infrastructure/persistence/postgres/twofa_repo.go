// TwoFA repo unifica admin_2fa + user_2fa (mesmas colunas, tabelas
// separadas por single-tenancy). Os métodos do RepositoryInterface
// detectam o subject e roteiam pra tabela certa.
//
// secret_encrypted é armazenado como hex (string) — não BYTEA — pra
// manter espelho byte-a-byte com o core legacy.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/jackc/pgx/v5"
)

type TwoFARepo struct{ db *DB }

func NewTwoFARepo(db *DB) *TwoFARepo { return &TwoFARepo{db: db} }

func (r *TwoFARepo) GetByUserID(ctx context.Context, userID string) (*domain.TwoFA, error) {
	row := r.db.pool.QueryRow(ctx, `
		SELECT secret_encrypted, COALESCE(backup_codes_hashed, '{}'), enrolled_at, last_used_at
		FROM user_2fa WHERE user_id=$1`, userID)
	return r.scanTwoFA(row, domain.Subject{Kind: domain.SubjectUser, UserID: userID})
}

func (r *TwoFARepo) GetByAdminID(ctx context.Context, adminID string) (*domain.TwoFA, error) {
	row := r.db.pool.QueryRow(ctx, `
		SELECT secret_encrypted, COALESCE(backup_codes_hashed, '{}'), enrolled_at, last_used_at
		FROM admin_2fa WHERE admin_id=$1`, adminID)
	return r.scanTwoFA(row, domain.Subject{Kind: domain.SubjectAdmin, AdminID: adminID})
}

func (r *TwoFARepo) UpsertUser(ctx context.Context, t domain.TwoFA) error {
	return r.upsert(ctx, "user_2fa", "user_id", t.UserID, t)
}

func (r *TwoFARepo) UpsertAdmin(ctx context.Context, t domain.TwoFA) error {
	return r.upsert(ctx, "admin_2fa", "admin_id", t.AdminID, t)
}

func (r *TwoFARepo) upsert(ctx context.Context, table, idCol, idVal string, t domain.TwoFA) error {
	query := fmt.Sprintf(`
		INSERT INTO %s (%s, secret_encrypted, backup_codes_hashed, enrolled_at, last_used_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (%s) DO UPDATE SET
			secret_encrypted = EXCLUDED.secret_encrypted,
			backup_codes_hashed = EXCLUDED.backup_codes_hashed,
			enrolled_at = EXCLUDED.enrolled_at,
			last_used_at = NOW()`, table, idCol, idCol)
	_, err := r.db.pool.Exec(ctx, query, idVal, t.EncryptedSecret, t.BackupCodesHash, t.EnrolledAt)
	return err
}

func (r *TwoFARepo) MarkEnrolled(ctx context.Context, subj domain.Subject, at time.Time) error {
	var table, idCol, idVal string
	if subj.Kind == domain.SubjectAdmin {
		table, idCol, idVal = "admin_2fa", "admin_id", subj.AdminID
	} else {
		table, idCol, idVal = "user_2fa", "user_id", subj.UserID
	}
	query := fmt.Sprintf(
		`UPDATE %s SET enrolled_at=$2, last_used_at=NOW() WHERE %s=$1`, table, idCol)
	tag, err := r.db.pool.Exec(ctx, query, idVal, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *TwoFARepo) Delete(ctx context.Context, subj domain.Subject) error {
	var table, idCol, idVal string
	if subj.Kind == domain.SubjectAdmin {
		table, idCol, idVal = "admin_2fa", "admin_id", subj.AdminID
	} else {
		table, idCol, idVal = "user_2fa", "user_id", subj.UserID
	}
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s=$1`, table, idCol)
	_, err := r.db.pool.Exec(ctx, query, idVal)
	return err
}

// ConsumeBackupCode remove o hash usado do array. Caller já validou o match.
func (r *TwoFARepo) ConsumeBackupCode(ctx context.Context, subj domain.Subject, hashOK string) error {
	var table, idCol, idVal string
	if subj.Kind == domain.SubjectAdmin {
		table, idCol, idVal = "admin_2fa", "admin_id", subj.AdminID
	} else {
		table, idCol, idVal = "user_2fa", "user_id", subj.UserID
	}
	query := fmt.Sprintf(`
		UPDATE %s
		SET backup_codes_hashed = array_remove(backup_codes_hashed, $2), last_used_at=NOW()
		WHERE %s=$1`, table, idCol)
	_, err := r.db.pool.Exec(ctx, query, idVal, hashOK)
	return err
}

func (r *TwoFARepo) scanTwoFA(row pgx.Row, subj domain.Subject) (*domain.TwoFA, error) {
	t := domain.TwoFA{
		SubjectKind: subj.Kind,
		UserID:      subj.UserID,
		AdminID:     subj.AdminID,
	}
	err := row.Scan(&t.EncryptedSecret, &t.BackupCodesHash, &t.EnrolledAt, &t.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}
