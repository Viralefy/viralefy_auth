package http

import (
	"net/http"
)

// NewRouter monta o mux com middleware InternalTokenAuth aplicado em
// /internal/v1/*. Health/ready ficam abertos (load balancer).
// JWKS público (read-only, sem secrets) também aberto pra verificadores externos.
func NewRouter(h *Handlers, internalSecret string) http.Handler {
	mux := http.NewServeMux()

	// Aberto: health/ready
	mux.HandleFunc("GET /internal/v1/health", h.Health)
	mux.HandleFunc("GET /internal/v1/ready", h.Ready)

	// Aberto: JWKS público
	mux.HandleFunc("GET /.well-known/jwks.json", h.JWKS)
	mux.HandleFunc("GET /internal/v1/jwks", h.JWKS)

	// Protegido por X-Internal-Token
	auth := InternalTokenAuth(internalSecret)
	mux.Handle("POST /internal/v1/login", auth(http.HandlerFunc(h.Login)))
	mux.Handle("POST /internal/v1/login/2fa", auth(http.HandlerFunc(h.Login2FA)))
	mux.Handle("POST /internal/v1/register", auth(http.HandlerFunc(h.Register)))
	mux.Handle("POST /internal/v1/refresh", auth(http.HandlerFunc(h.Refresh)))
	mux.Handle("POST /internal/v1/logout", auth(http.HandlerFunc(h.Logout)))
	mux.Handle("POST /internal/v1/token/verify", auth(http.HandlerFunc(h.TokenVerify)))
	mux.Handle("POST /internal/v1/token/revoke", auth(http.HandlerFunc(h.TokenRevoke)))
	mux.Handle("POST /internal/v1/password/reset/request", auth(http.HandlerFunc(h.PasswordResetRequest)))
	mux.Handle("POST /internal/v1/password/reset/confirm", auth(http.HandlerFunc(h.PasswordResetConfirm)))
	mux.Handle("POST /internal/v1/twofa/enroll", auth(http.HandlerFunc(h.TwoFAEnroll)))
	mux.Handle("POST /internal/v1/twofa/verify", auth(http.HandlerFunc(h.TwoFAVerify)))
	mux.Handle("POST /internal/v1/twofa/disable", auth(http.HandlerFunc(h.TwoFADisable)))

	return mux
}
