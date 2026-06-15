// viralefy_auth — serviço de identidade do Viralefy.
//
// Responsabilidades:
//   - Mint + verify de JWT (RS256 + JWKS público)
//   - Login / Register / Refresh / Logout
//   - 2FA TOTP (enroll, verify, disable, backup codes)
//   - Password reset (request + confirm)
//   - Hot-set de revogação via tabela revoked_jtis
//
// Princípios:
//   - Superfície mínima. Sem business logic além de identidade.
//   - Bind loopback :8083 — não exposto na internet.
//   - INTERNAL_SHARED_SECRET em todo request entre api↔auth e core↔auth.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Viralefy/viralefy_auth/internal/application"
	"github.com/Viralefy/viralefy_auth/internal/config"
	"github.com/Viralefy/viralefy_auth/internal/infrastructure/jwtkeys"
	"github.com/Viralefy/viralefy_auth/internal/infrastructure/observability"
	"github.com/Viralefy/viralefy_auth/internal/infrastructure/persistence/postgres"
	authhttp "github.com/Viralefy/viralefy_auth/internal/interface/http"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "viralefy-auth", "version", appVersion())
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// CLI subcommands.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "version":
			logger.Info("viralefy-auth version", "version", appVersion())
			return
		}
	}

	// Hard-required pra subir o stack completo.
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	if cfg.InternalSharedSecret == "" {
		log.Fatal("INTERNAL_SHARED_SECRET is required")
	}

	// Prometheus collectors — registrados antes de servir requests pra
	// /internal/metrics não 404ar enquanto handlers ainda warming up.
	observability.InitMetrics()

	ctx := context.Background()

	// Postgres.
	db, err := postgres.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer db.Close()
	if err := db.AssertSchema(ctx); err != nil {
		log.Fatalf("schema assert: %v", err)
	}

	// JWT keys.
	priv, err := jwtkeys.LoadOrGenerate(cfg.JWTPrivateKeyPath)
	if err != nil {
		log.Fatalf("jwt key: %v", err)
	}

	// TTLs.
	accessTTL, err := time.ParseDuration(cfg.AccessTokenTTL)
	if err != nil {
		log.Fatalf("invalid VAUTH_ACCESS_TOKEN_TTL: %v", err)
	}
	refreshTTL, err := time.ParseDuration(cfg.RefreshTokenTTL)
	if err != nil {
		log.Fatalf("invalid VAUTH_REFRESH_TOKEN_TTL: %v", err)
	}

	// Repos.
	userRepo := postgres.NewUserRepo(db)
	adminRepo := postgres.NewAdminRepo(db)
	refreshRepo := postgres.NewRefreshTokenRepo(db)
	revokedRepo := postgres.NewRevokedJTIRepo(db)
	passResetRepo := postgres.NewPasswordResetRepo(db)
	twofaRepo := postgres.NewTwoFARepo(db)

	// TwoFA encryption key — aceita hex (64 chars) ou base64 (44/43 chars).
	// AES-256-GCM exige exatamente 32 bytes (256 bits) decodificados; passar
	// a string raw ([]byte do hex) gerava 64 bytes e Decrypt falhava com
	// "key must be 32 bytes" → 500 no /v1/auth/user/login/2fa. Espelha o
	// formato parse2FAKey do viralefy_core pra os 2 services usarem a MESMA
	// chave canônica.
	encKey, err := parse2FAKey(cfg.TwoFAEncKey)
	if err != nil {
		logger.Warn("TWOFA_ENCRYPTION_KEY inválida — 2FA endpoints retornarão 500", slog.String("error", err.Error()))
	}

	// Services.
	tokenSvc := application.NewTokenService(application.TokenServiceConfig{
		PrivKey:       priv,
		AccessTTL:     accessTTL,
		RefreshTTL:    refreshTTL,
		RefreshTokens: refreshRepo,
		RevokedJTIs:   revokedRepo,
		// Round 25 HIGH fix: Refresh re-busca role/email reais do
		// user/admin pra não re-emitir token com role default genérico.
		Users:         userRepo,
		Admins:        adminRepo,
	})
	authSvc := application.NewAuthService(userRepo, adminRepo, twofaRepo, passResetRepo, tokenSvc, encKey)

	// HTTP.
	h := &authhttp.Handlers{Auth: authSvc}
	router := authhttp.NewRouter(h, cfg.InternalSharedSecret)

	srv := &http.Server{
		Addr:              cfg.BindAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	// Graceful shutdown.
	ctx2, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("viralefy-auth listening",
			"addr", cfg.BindAddr,
			"jwt_kid", jwtkeys.KeyID(priv),
			"access_ttl", accessTTL.String(),
			"refresh_ttl", refreshTTL.String())
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server error", "error", err.Error())
			os.Exit(1)
		}
	}()

	<-ctx2.Done()
	logger.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

func appVersion() string {
	if v := os.Getenv("APP_VERSION"); v != "" {
		return v
	}
	return "dev"
}

// parse2FAKey aceita hex 64 chars OU base64 44 (com padding) / 43 (sem).
// Espelha viralefy_core/internal/config.parse2FAKey — manter sincronizado.
// Retorna []byte len=32 ou erro.
func parse2FAKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("TWOFA_ENCRYPTION_KEY must decode to 32 bytes (hex 64 or base64 44/43 chars)")
}
