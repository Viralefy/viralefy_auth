// Package postgres — pool compartilhado + schema assertions.
//
// Auth NÃO aplica DDL — core é dono. Boot do auth verifica que tabelas
// críticas existem (`refresh_tokens`, `revoked_jtis`, `password_resets`,
// `users`, `admins`, `admin_2fa`, `user_2fa`, `audit_log`). Falha-fast
// se schema estiver atrás do esperado — evita rodar com features ausentes.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse db url: %w", err)
	}
	// Defensive defaults — sender/payments usam similar. Auth é hot-path
	// de login → pool generoso pra evitar saturation em pico de tráfego.
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.MaxConnLifetime = 1 * time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("new pool: %w", err)
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (d *DB) Pool() *pgxpool.Pool { return d.pool }
func (d *DB) Close()              { d.pool.Close() }

// AssertSchema valida que as tabelas exigidas pelo auth existem. Roda no
// boot; se faltar alguma o processo aborta com mensagem clara —
// proteção contra esquecer de rodar a migration 039 no DB de dev.
func (d *DB) AssertSchema(ctx context.Context) error {
	required := []string{
		"users", "admins",
		"refresh_tokens", "revoked_jtis", "password_resets",
		"admin_2fa", "user_2fa",
		"audit_log",
	}
	for _, t := range required {
		var exists bool
		err := d.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema='public' AND table_name=$1
			)`, t).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check table %s: %w", t, err)
		}
		if !exists {
			return fmt.Errorf("table %q does not exist — run 'viralefy-core migrate up' first", t)
		}
	}
	return nil
}
