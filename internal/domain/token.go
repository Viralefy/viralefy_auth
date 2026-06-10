package domain

import (
	"context"
	"time"
)

// Subject — quem é o dono do token. Exatamente um dos dois IDs preenchido.
type SubjectKind string

const (
	SubjectUser  SubjectKind = "user"
	SubjectAdmin SubjectKind = "admin"
)

type Subject struct {
	Kind    SubjectKind
	UserID  string // populado quando Kind == SubjectUser
	AdminID string // populado quando Kind == SubjectAdmin
	// SubjectIDExposed devolve o ID concreto (UserID ou AdminID) pra colocar em claim `sub`.
}

func (s Subject) ID() string {
	if s.Kind == SubjectAdmin {
		return s.AdminID
	}
	return s.UserID
}

// AccessClaims é o payload do access token (RS256). Mesma forma que o core
// usa hoje — backward-compat total com tokens em circulação.
type AccessClaims struct {
	Sub   string      `json:"sub"`
	Typ   string      `json:"typ,omitempty"`   // "admin", "admin_partial", "user", "user_partial"
	Role  string      `json:"role,omitempty"`  // admin role; "user" pra users
	Email string      `json:"email,omitempty"`
	Exp   int64       `json:"exp"`
	Iat   int64       `json:"iat"`
	Jti   string      `json:"jti,omitempty"`
}

// RefreshToken é o registro persistido (token bruto JAMAIS armazenado —
// só o SHA256 dele).
type RefreshToken struct {
	ID             string
	TokenHash      string
	UserID         *string
	AdminID        *string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	ReplacedByID   *string
	IssueIP        string
	IssueUserAgent string
}

func (r RefreshToken) IsActive() bool {
	if r.RevokedAt != nil {
		return false
	}
	return time.Now().UTC().Before(r.ExpiresAt)
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, t RefreshToken) error
	GetByHash(ctx context.Context, hash string) (*RefreshToken, error)
	Revoke(ctx context.Context, id, replacedBy string) error
	RevokeBySubject(ctx context.Context, subj Subject) error
}

// RevokedJTI é uma linha do hot-set consultado pelo dispatcher.
type RevokedJTI struct {
	JTI         string
	ExpiresAt   time.Time
	RevokedAt   time.Time
	Reason      string
	ByAdminID   *string
	ByUserID    *string
}

type RevokedJTIRepository interface {
	Add(ctx context.Context, r RevokedJTI) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
	ListActive(ctx context.Context) ([]RevokedJTI, error)
}

// PasswordReset — token de reset, hash SHA256, single-use.
type PasswordReset struct {
	ID                  string
	TokenHash           string
	UserID              *string
	AdminID             *string
	RequestedAt         time.Time
	ExpiresAt           time.Time
	UsedAt              *time.Time
	RequestedIP         string
	RequestedUserAgent  string
}

type PasswordResetRepository interface {
	Create(ctx context.Context, p PasswordReset) error
	GetByHash(ctx context.Context, hash string) (*PasswordReset, error)
	MarkUsed(ctx context.Context, id string) error
}
