package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/google/uuid"
)

// writeJSON serializa em JSON com status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		TraceID string `json:"trace_id,omitempty"`
	} `json:"error"`
}

// writeError mapeia erros canônicos do domain pra HTTP. Mantém mesma
// taxonomia que o core (manter contratos consistentes pro dispatcher).
func writeError(w http.ResponseWriter, err error) {
	trace := uuid.New().String()
	status := http.StatusInternalServerError
	code := "INTERNAL_ERROR"
	msg := "internal server error"

	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		status, code, msg = http.StatusUnprocessableEntity, "INVALID_INPUT", err.Error()
	case errors.Is(err, domain.ErrUnauthorized):
		status, code, msg = http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized"
	case errors.Is(err, domain.ErrNotFound):
		status, code, msg = http.StatusNotFound, "NOT_FOUND", err.Error()
	case errors.Is(err, domain.ErrConflict):
		// Tira o sufixo ": conflict" quando o err vem de fmt.Errorf("...: %w", ErrConflict).
		// Fica "email already registered" em vez de "email already registered: conflict".
		status, code = http.StatusConflict, "CONFLICT"
		msg = strings.TrimSuffix(err.Error(), ": "+domain.ErrConflict.Error())
	case errors.Is(err, domain.ErrTwoFARequired):
		status, code, msg = http.StatusUnauthorized, "TWOFA_REQUIRED", "two-factor authentication required"
	case errors.Is(err, domain.ErrTwoFAAlreadyEnrolled):
		status, code, msg = http.StatusConflict, "TWOFA_ALREADY_ENROLLED", "2FA already enrolled"
	case errors.Is(err, domain.ErrTwoFANotEnrolled):
		status, code, msg = http.StatusUnprocessableEntity, "TWOFA_NOT_ENROLLED", "2FA not enrolled"
	case errors.Is(err, domain.ErrInvalidTwoFACode):
		status, code, msg = http.StatusUnauthorized, "INVALID_TWOFA_CODE", "invalid two-factor code"
	case errors.Is(err, domain.ErrTokenExpired):
		status, code, msg = http.StatusUnauthorized, "TOKEN_EXPIRED", "token expired"
	case errors.Is(err, domain.ErrTokenRevoked):
		status, code, msg = http.StatusUnauthorized, "TOKEN_REVOKED", "token revoked"
	case errors.Is(err, domain.ErrTokenMalformed):
		status, code, msg = http.StatusBadRequest, "TOKEN_MALFORMED", "token malformed"
	}

	body := errorBody{}
	body.Error.Code = code
	body.Error.Message = msg
	body.Error.TraceID = trace
	writeJSON(w, status, body)
}
