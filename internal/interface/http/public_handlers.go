package http

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/Viralefy/viralefy_auth/internal/domain"
)

// Public handlers — endpoints expostos diretamente ao mundo externo (sem
// X-Internal-Token). Espelham os internal /login,/register,/login/2fa mas:
//   - Não aceitam campo `kind` no body — derivam do path (/v1/auth/user/* vs /v1/auth/*)
//   - Rate-limit por IP (in-memory; janela deslizante simples)
//   - Response shape idêntico ao dos internal handlers (reuso de loginResponse)
//
// Esses handlers existem pro dispatcher/Caddy poder dar cutover do legacy api
// para viralefy_auth sem mudar contrato de cliente (front/backoffice).

// ─── Rate limiter ────────────────────────────────────────────────────
//
// Janela deslizante in-memory por IP. 10 tentativas / 15 min, igual ao
// login_limiter do legacy. Sem dependência externa.

type ipRateLimiter struct {
	mu       sync.Mutex
	hits     map[string][]time.Time
	limit    int
	window   time.Duration
	lastSwp  time.Time
	sweepInt time.Duration
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		hits:     make(map[string][]time.Time),
		limit:    limit,
		window:   window,
		sweepInt: 5 * time.Minute,
		lastSwp:  time.Now(),
	}
}

// Allow registra um hit e devolve true se ainda dentro do budget.
func (l *ipRateLimiter) Allow(ip string) bool {
	if ip == "" {
		ip = "unknown"
	}
	now := time.Now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	// Sweep periódico pra não vazar IPs antigos.
	if now.Sub(l.lastSwp) > l.sweepInt {
		for k, ts := range l.hits {
			kept := ts[:0]
			for _, t := range ts {
				if t.After(cutoff) {
					kept = append(kept, t)
				}
			}
			if len(kept) == 0 {
				delete(l.hits, k)
			} else {
				l.hits[k] = kept
			}
		}
		l.lastSwp = now
	}
	ts := l.hits[ip]
	kept := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.hits[ip] = kept
		return false
	}
	l.hits[ip] = append(kept, now)
	return true
}

// PublicLimiter é o limiter global usado pelos handlers públicos. Compartilhado
// entre user/admin login e register pra alinhar com o limiter unificado do legacy.
var PublicLimiter = newIPRateLimiter(10, 15*time.Minute)

func writeRateLimited(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":{"code":"RATE_LIMITED","message":"too many requests"}}`))
}

// ─── Public handlers ─────────────────────────────────────────────────

// publicLoginRequest — sem campo `kind`; derivado do path.
type publicLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// PublicUserLogin — POST /v1/auth/user/login
func (h *Handlers) PublicUserLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !PublicLimiter.Allow(ip) {
		writeRateLimited(w)
		return
	}
	var req publicLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	ua := r.Header.Get("User-Agent")
	res, err := h.Auth.LoginUser(r.Context(), req.Email, req.Password, ip, ua)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse(res))
}

// PublicAdminLogin — POST /v1/auth/login
func (h *Handlers) PublicAdminLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !PublicLimiter.Allow(ip) {
		writeRateLimited(w)
		return
	}
	var req publicLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	ua := r.Header.Get("User-Agent")
	res, err := h.Auth.LoginAdmin(r.Context(), req.Email, req.Password, ip, ua)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse(res))
}

// PublicLogin2FA — POST /v1/auth/user/login/2fa  e  POST /v1/auth/login/2fa
// Mesmo handler — derivação de user/admin vem do PartialToken.
func (h *Handlers) PublicLogin2FA(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !PublicLimiter.Allow(ip) {
		writeRateLimited(w)
		return
	}
	var req login2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	ua := r.Header.Get("User-Agent")
	res, err := h.Auth.CompleteLogin2FA(r.Context(), req.PartialToken, req.Code, ip, ua)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse(res))
}

// publicRegisterRequest — body do autocadastro público de user.
// Mantém phone/telegram/name opcionais pra compat com legacy que aceitava só
// email+password. Application layer aplica regras (phone OR telegram obrigatório).
type publicRegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Phone    string `json:"phone"`
	Telegram string `json:"telegram"`
}

// PublicUserRegister — POST /v1/auth/user/register
func (h *Handlers) PublicUserRegister(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !PublicLimiter.Allow(ip) {
		writeRateLimited(w)
		return
	}
	var req publicRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	ua := r.Header.Get("User-Agent")
	res, err := h.Auth.RegisterUser(r.Context(), req.Email, req.Password, req.Name, req.Phone, req.Telegram, ip, ua)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, loginResponse(res))
}

// publicAdminEnroll2FARequest — usa apenas partial_token; subject é derivado
// do partial_token (caso admin obrigado a 2FA ainda não enrolado).
type publicAdminEnroll2FARequest struct {
	PartialToken string `json:"partial_token"`
}

// PublicAdminEnroll2FA — POST /v1/auth/login/2fa/enroll
// Flow: admin com requires_2fa=true mas sem enrollment → /v1/auth/login devolve
// partial_token; admin chama esse endpoint pra obter secret+otpauth_url+backup
// codes. Depois finaliza login via /v1/auth/login/2fa com o código gerado.
func (h *Handlers) PublicAdminEnroll2FA(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !PublicLimiter.Allow(ip) {
		writeRateLimited(w)
		return
	}
	var req publicAdminEnroll2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PartialToken == "" {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	subj, err := h.Auth.Tokens().ParsePartialToken(req.PartialToken)
	if err != nil {
		writeError(w, err)
		return
	}
	// Endpoint é exclusivo do flow admin (legacy expunha só /v1/auth/login/2fa/enroll).
	if subj.Kind != domain.SubjectAdmin || subj.AdminID == "" {
		writeError(w, domain.ErrUnauthorized)
		return
	}
	res, err := h.Auth.Enroll2FA(r.Context(), subj)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
