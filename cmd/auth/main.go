// viralefy_auth — serviço de identidade do Viralefy.
//
// Responsabilidades (escopo Fase 9b):
//   - Mint + verify de JWT (RS256)
//   - Login / Register / Refresh / Logout
//   - 2FA TOTP (enroll, verify, disable, backup codes)
//   - Password reset (request + confirm)
//   - Audit log de eventos de auth (succesful login, failed, 2fa events)
//   - Hot-set de revogação via tabela revoked_jtis (não memória)
//   - Expor JWKS público pra verificadores externos
//
// Princípios:
//   - Superfície mínima. Sem business logic além de identidade.
//   - Bind loopback :8083 — não exposto na internet. Caddy + api dispatcher
//     fazem proxy seletivo das rotas públicas.
//   - INTERNAL_SHARED_SECRET em todo request entre api↔auth e core↔auth.
//   - Log estruturado de TODAS tentativas de auth (sucesso e falha).
//   - Chave RS256 mestre carregada de /etc/viralefy/keys/jwt-rs256.pem
//     (mesma do core durante janela de cutover ≤14d).
package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Viralefy/viralefy_auth/internal/config"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("service", "viralefy-auth", "version", appVersion())
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// CLI subcommands (mesmo pattern do core).
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "migrate":
			logger.Info("migrate command not implemented yet — schema shared with viralefy_core (single Postgres)")
			os.Exit(0)
		case "version":
			logger.Info("viralefy-auth version", "version", appVersion())
			os.Exit(0)
		}
	}

	// HTTP server scaffold — handlers reais entram nos próximos commits.
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"viralefy-auth","stage":"scaffold"}`))
	})
	mux.HandleFunc("/internal/v1/ready", func(w http.ResponseWriter, r *http.Request) {
		// Próxima fase: ping DB + check key file existence
		w.Write([]byte(`{"ready":true}`))
	})

	srv := &http.Server{
		Addr:              cfg.BindAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	// Graceful shutdown (SIGTERM = systemd stop).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("viralefy-auth listening", "addr", cfg.BindAddr, "stage", "scaffold")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server error", "error", err.Error())
			os.Exit(1)
		}
	}()

	<-ctx.Done()
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
