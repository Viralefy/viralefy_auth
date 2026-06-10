package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Viralefy/viralefy_auth/internal/application"
	"github.com/Viralefy/viralefy_auth/internal/domain"
)

// Handlers carrega as deps necessárias pelos endpoints HTTP.
// Tipo único pra não dar pop-up de injeção em cada função; main.go monta.
type Handlers struct {
	Auth *application.AuthService
}

// ────────────────────────────────────────────────────────────────
//
// Health endpoints — sem auth, usados por load balancer / dispatcher.

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "viralefy-auth",
	})
}

func (h *Handlers) Ready(w http.ResponseWriter, r *http.Request) {
	// Próximas iterações: pingar DB + check JWT key file.
	writeJSON(w, http.StatusOK, map[string]bool{"ready": true})
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/login (user OR admin)

type loginRequest struct {
	Email   string `json:"email"`
	Password string `json:"password"`
	Kind    string `json:"kind"` // "user" | "admin"
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	ip, ua := clientIP(r), r.Header.Get("User-Agent")
	var (
		res *application.LoginResult
		err error
	)
	switch strings.ToLower(req.Kind) {
	case "admin":
		res, err = h.Auth.LoginAdmin(r.Context(), req.Email, req.Password, ip, ua)
	default:
		res, err = h.Auth.LoginUser(r.Context(), req.Email, req.Password, ip, ua)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse(res))
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/login/2fa — complete partial token + TOTP

type login2FARequest struct {
	PartialToken string `json:"partial_token"`
	Code         string `json:"code"`
}

func (h *Handlers) Login2FA(w http.ResponseWriter, r *http.Request) {
	var req login2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	ip, ua := clientIP(r), r.Header.Get("User-Agent")
	res, err := h.Auth.CompleteLogin2FA(r.Context(), req.PartialToken, req.Code, ip, ua)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse(res))
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/register (user only)

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Phone    string `json:"phone"`
	Telegram string `json:"telegram"`
}

func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	ip, ua := clientIP(r), r.Header.Get("User-Agent")
	res, err := h.Auth.RegisterUser(r.Context(), req.Email, req.Password, req.Name, req.Phone, req.Telegram, ip, ua)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, loginResponse(res))
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/refresh — rotaciona refresh token

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	ip, ua := clientIP(r), r.Header.Get("User-Agent")
	// Refresh interno do TokenService já valida + revoga + emite par novo.
	sess, err := h.Auth.Tokens().Refresh(r.Context(), req.RefreshToken, ip, ua)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":       sess.AccessToken,
		"access_expires_at":  sess.AccessExpiresAt,
		"refresh_token":      sess.RefreshToken,
		"refresh_expires_at": sess.RefreshExpiresAt,
	})
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/logout — revoga refresh + access JTI atual

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	var accessJTI string
	var accessExp time.Time
	if req.AccessToken != "" {
		// Verify aceita revogados/expirados pra extrair claims (logout idempotente).
		// Aqui usamos VerifyAccess que rejeita revogados — fallback parseclaims sem verify? Keep simple.
		if c, err := h.Auth.Tokens().VerifyAccess(r.Context(), req.AccessToken); err == nil || errors.Is(err, domain.ErrTokenRevoked) {
			accessJTI = c.Jti
			accessExp = time.Unix(c.Exp, 0)
		}
	}
	_ = h.Auth.Tokens().Logout(r.Context(), req.RefreshToken, accessJTI, accessExp)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/token/verify — dispatcher consulta aqui pra validar access

type verifyRequest struct {
	Token string `json:"token"`
}

type verifyResponse struct {
	Valid  bool                   `json:"valid"`
	Claims *domain.AccessClaims   `json:"claims,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

func (h *Handlers) TokenVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		writeJSON(w, http.StatusOK, verifyResponse{Valid: false, Error: "invalid_input"})
		return
	}
	c, err := h.Auth.Tokens().VerifyAccess(r.Context(), req.Token)
	if err != nil {
		writeJSON(w, http.StatusOK, verifyResponse{Valid: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{Valid: true, Claims: c})
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/token/revoke — força revogação de um JTI

type revokeRequest struct {
	JTI       string `json:"jti"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds; max TTL do token original
	Reason    string `json:"reason"`
}

func (h *Handlers) TokenRevoke(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.JTI == "" {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	if err := h.Auth.Tokens().RevokeAccessJTI(r.Context(), req.JTI, time.Unix(req.ExpiresAt, 0), req.Reason); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/password/reset/request

type passwordResetRequestRequest struct {
	Email string `json:"email"`
}

func (h *Handlers) PasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	ip, ua := clientIP(r), r.Header.Get("User-Agent")
	issued, u, a, err := h.Auth.RequestPasswordReset(r.Context(), req.Email, ip, ua)
	if err != nil {
		writeError(w, err)
		return
	}
	// Anti-enum: resposta success seja qual for o resultado. Email externo
	// fica a cargo do caller (core/dispatcher) — auth devolve o token bruto
	// (sob X-Internal-Token, só acessível em rede interna).
	resp := map[string]any{"ok": true}
	if issued != nil {
		resp["token_raw"] = issued.TokenRaw
		if u != nil {
			resp["email"] = u.Email
			resp["subject_kind"] = "user"
		}
		if a != nil {
			resp["email"] = a.Email
			resp["subject_kind"] = "admin"
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/password/reset/confirm

type passwordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (h *Handlers) PasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	var req passwordResetConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	if err := h.Auth.ConfirmPasswordReset(r.Context(), req.Token, req.NewPassword); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/twofa/enroll — gera secret + backup codes (UMA vez)

type twofaEnrollRequest struct {
	SubjectKind string `json:"subject_kind"` // "user" | "admin"
	SubjectID   string `json:"subject_id"`
}

func (h *Handlers) TwoFAEnroll(w http.ResponseWriter, r *http.Request) {
	var req twofaEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	subj := subjectFromReq(req.SubjectKind, req.SubjectID)
	if subj.ID() == "" {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	res, err := h.Auth.Enroll2FA(r.Context(), subj)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/twofa/verify

type twofaVerifyRequest struct {
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
	Code        string `json:"code"`
}

func (h *Handlers) TwoFAVerify(w http.ResponseWriter, r *http.Request) {
	var req twofaVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	subj := subjectFromReq(req.SubjectKind, req.SubjectID)
	if err := h.Auth.Verify2FA(r.Context(), subj, req.Code); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ────────────────────────────────────────────────────────────────
//
// /internal/v1/twofa/disable

type twofaDisableRequest struct {
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
}

func (h *Handlers) TwoFADisable(w http.ResponseWriter, r *http.Request) {
	var req twofaDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, domain.ErrInvalidInput)
		return
	}
	subj := subjectFromReq(req.SubjectKind, req.SubjectID)
	if err := h.Auth.Disable2FA(r.Context(), subj); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ────────────────────────────────────────────────────────────────
//
// JWKS público — proxy do dispatcher. Caddy expõe via /well-known.

func (h *Handlers) JWKS(w http.ResponseWriter, r *http.Request) {
	keys, err := h.Auth.Tokens().PublicJWKS()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

// ─── Helpers ─────────────────────────────────────────────────────

func subjectFromReq(kind, id string) domain.Subject {
	if strings.ToLower(kind) == "admin" {
		return domain.Subject{Kind: domain.SubjectAdmin, AdminID: id}
	}
	return domain.Subject{Kind: domain.SubjectUser, UserID: id}
}

func loginResponse(res *application.LoginResult) map[string]any {
	out := map[string]any{}
	if res.TwoFARequired {
		out["twofa_required"] = true
		out["partial_token"] = res.PartialToken
		return out
	}
	if res.Session != nil {
		out["access_token"] = res.Session.AccessToken
		out["access_expires_at"] = res.Session.AccessExpiresAt
		out["refresh_token"] = res.Session.RefreshToken
		out["refresh_expires_at"] = res.Session.RefreshExpiresAt
	}
	if res.UserView != nil {
		out["subject_kind"] = "user"
		out["user"] = res.UserView
	}
	if res.AdminView != nil {
		out["subject_kind"] = "admin"
		out["admin"] = res.AdminView
	}
	return out
}
