package domain

import (
	"context"
	"time"
)

// TwoFA é o registro espelhando admin_2fa / user_2fa.
type TwoFA struct {
	SubjectKind     SubjectKind
	UserID          string
	AdminID         string
	EncryptedSecret string     // AES-256-GCM hex (igual core, coluna `secret_encrypted`)
	BackupCodesHash []string   // bcrypt hash de cada código (coluna `backup_codes_hashed`)
	EnrolledAt      *time.Time // null até /verify primeira passar
	LastUsedAt      *time.Time // null até primeiro success do TOTP
}

// IsEnrolled é true só quando EnrolledAt != nil. Antes do user
// completar /verify, fica em "enroll started but not confirmed".
func (t TwoFA) IsEnrolled() bool {
	return t.EnrolledAt != nil
}

type TwoFARepository interface {
	GetByUserID(ctx context.Context, userID string) (*TwoFA, error)
	GetByAdminID(ctx context.Context, adminID string) (*TwoFA, error)
	UpsertUser(ctx context.Context, t TwoFA) error
	UpsertAdmin(ctx context.Context, t TwoFA) error
	MarkEnrolled(ctx context.Context, subj Subject, at time.Time) error
	Delete(ctx context.Context, subj Subject) error
	ConsumeBackupCode(ctx context.Context, subj Subject, hashOK string) error
}
