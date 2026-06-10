package postgres

import (
	"context"
	"errors"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/jackc/pgx/v5"
)

type UserRepo struct{ db *DB }

func NewUserRepo(db *DB) *UserRepo { return &UserRepo{db: db} }

// Apenas os campos que auth precisa. Outros (instagram, créditos, etc) viram
// no core. Note que `name` é NOT NULL no schema do core; auth usa "" se vazio.
const userCols = `id, email, name, password_hash,
	COALESCE(phone, '') AS phone, COALESCE(telegram, '') AS telegram,
	created_at, deleted_at`

func (r *UserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	row := r.db.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id)
	return scanUser(row)
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	row := r.db.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE email=$1`, email)
	return scanUser(row)
}

func (r *UserRepo) Create(ctx context.Context, u domain.User) error {
	// instagram é NOT NULL no schema mas auth não cuida disso — deixa "".
	_, err := r.db.pool.Exec(ctx, `
		INSERT INTO users (id, email, name, password_hash, instagram, phone, telegram)
		VALUES ($1, $2, $3, $4, '', NULLIF($5, ''), NULLIF($6, ''))`,
		u.ID, u.Email, u.Name, u.PasswordHash, u.Phone, u.Telegram)
	return err
}

func (r *UserRepo) UpdatePasswordHash(ctx context.Context, id, newHash string) error {
	tag, err := r.db.pool.Exec(ctx, `
		UPDATE users SET password_hash=$2 WHERE id=$1 AND deleted_at IS NULL`,
		id, newHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Phone, &u.Telegram, &u.CreatedAt, &u.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}
