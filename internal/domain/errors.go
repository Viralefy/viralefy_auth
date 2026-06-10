// Package domain — tipos e erros do core do auth.
package domain

import "errors"

// Erros canônicos retornados pelos services. Handlers HTTP mapeiam pra status.
var (
	ErrInvalidInput     = errors.New("invalid_input")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrNotFound         = errors.New("not_found")
	ErrConflict         = errors.New("conflict")
	ErrTwoFARequired    = errors.New("twofa_required")
	ErrTwoFAAlreadyEnrolled = errors.New("twofa_already_enrolled")
	ErrTwoFANotEnrolled = errors.New("twofa_not_enrolled")
	ErrInvalidTwoFACode = errors.New("invalid_twofa_code")
	ErrTokenExpired     = errors.New("token_expired")
	ErrTokenRevoked     = errors.New("token_revoked")
	ErrTokenMalformed   = errors.New("token_malformed")
)
