// Package config carrega config do viralefy_auth via env.
//
// Convenção: prefixo VAUTH_ pra evitar colisão com env do core/api/payments/sender.
// Algumas envs são compartilhadas explicitamente (DATABASE_URL, INTERNAL_SHARED_SECRET,
// TWOFA_ENCRYPTION_KEY) — auth lê o mesmo arquivo /etc/viralefy/.env do core durante
// a janela de cutover Fase 9b. Após cutover, auth pode receber seu próprio .env.
package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	BindAddr             string // VAUTH_BIND_ADDR, default 127.0.0.1:8083
	DatabaseURL          string // DATABASE_URL (compartilhado com core)
	InternalSharedSecret string // INTERNAL_SHARED_SECRET (compartilhado)
	JWTPrivateKeyPath    string // JWT_PRIVATE_KEY_PATH (compartilhado durante cutover)
	JWTKeyID             string // VAUTH_JWT_KID, opcional — auto-derivado se vazio
	TwoFAEncKey          string // TWOFA_ENCRYPTION_KEY (compartilhado)
	AccessTokenTTL       string // VAUTH_ACCESS_TOKEN_TTL, default 15m
	RefreshTokenTTL      string // VAUTH_REFRESH_TOKEN_TTL, default 30d
	ResendAPIKey         string // RESEND_API_KEY (password reset emails)
	ResendFrom           string // RESEND_FROM
	SentryDSN            string // SENTRY_DSN (opt-in)
}

func Load() (*Config, error) {
	c := &Config{
		BindAddr:             getenv("VAUTH_BIND_ADDR", "127.0.0.1:8083"),
		DatabaseURL:          os.Getenv("DATABASE_URL"),
		InternalSharedSecret: os.Getenv("INTERNAL_SHARED_SECRET"),
		JWTPrivateKeyPath:    getenv("JWT_PRIVATE_KEY_PATH", "/etc/viralefy/jwt-rs256.pem"),
		JWTKeyID:             os.Getenv("VAUTH_JWT_KID"),
		TwoFAEncKey:          os.Getenv("TWOFA_ENCRYPTION_KEY"),
		AccessTokenTTL:       getenv("VAUTH_ACCESS_TOKEN_TTL", "15m"),
		RefreshTokenTTL:      getenv("VAUTH_REFRESH_TOKEN_TTL", "720h"),
		ResendAPIKey:         os.Getenv("RESEND_API_KEY"),
		ResendFrom:           getenv("RESEND_FROM", "contato@viralefy.com"),
		SentryDSN:            os.Getenv("SENTRY_DSN"),
	}

	// Validações em scaffold mode: só campos essenciais pra subir health.
	// As outras viram strictly required quando os respectivos handlers entrarem
	// (login = precisa DB, etc).
	missing := []string{}
	for _, pair := range [][2]string{
		// ⚠️ scaffold: nenhum env é hard-required ainda — health check funciona com defaults.
		// Quando handlers entrarem, mover envs críticas pra esta lista.
	} {
		if pair[1] == "" {
			missing = append(missing, pair[0])
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("config: faltam envs obrigatórias: %s", strings.Join(missing, ", "))
	}
	return c, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
