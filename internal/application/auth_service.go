package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/Viralefy/viralefy_auth/internal/infrastructure/external/totp"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthService orquestra os fluxos de identidade. Composto sobre TokenService
// (responsável pelo crypto de JWT) + os repos. Encapsula:
//   - Login user/admin com 2FA opcional ou obrigatório
//   - Register user (com phone/telegram obrigatório, igual core)
//   - Refresh token rotation
//   - 2FA enroll / verify / disable / backup codes
//   - Password reset request/confirm
//
// Não conhece HTTP — handlers traduzem erros e shapes.
type AuthService struct {
	users         domain.UserRepository
	admins        domain.AdminRepository
	twofa         domain.TwoFARepository
	passResets    domain.PasswordResetRepository
	tokens        *TokenService
	encKey        []byte
}

func NewAuthService(
	users domain.UserRepository,
	admins domain.AdminRepository,
	twofa domain.TwoFARepository,
	passResets domain.PasswordResetRepository,
	tokens *TokenService,
	encKey []byte,
) *AuthService {
	return &AuthService{users: users, admins: admins, twofa: twofa, passResets: passResets, tokens: tokens, encKey: encKey}
}

// Tokens expõe o TokenService pros handlers usarem refresh/verify/revoke direto.
func (s *AuthService) Tokens() *TokenService { return s.tokens }

// LoginResult contém todos os possíveis estados do /login.
// - Session != nil  → login completo (sem 2FA, ou 2FA ainda não habilitado)
// - PartialToken != "" → /login parcial, cliente precisa rodar /login/2fa
type LoginResult struct {
	Session       *MintedSession
	PartialToken  string
	TwoFARequired bool
	UserView      *UserView  // populado quando Session != nil e Kind=user
	AdminView     *AdminView // populado quando Session != nil e Kind=admin
}

type UserView struct {
	ID       string
	Email    string
	Name     string
	Phone    string
	Telegram string
}

type AdminView struct {
	ID          string
	Email       string
	Name        string
	Role        string
	Permissions []string // populado pelo caller via roles repo no core; aqui vazio
}

// LoginUser autentica um user (loja). Email + senha; se 2FA enrolled,
// devolve PartialToken pra cliente chamar /login/2fa.
func (s *AuthService) LoginUser(ctx context.Context, email, password, ip, ua string) (*LoginResult, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || password == "" {
		return nil, domain.ErrInvalidInput
	}
	u, err := s.users.GetByEmail(ctx, email)
	if err != nil || u == nil {
		// Mesmo erro pra not-found e bad-password (anti-enum).
		return nil, domain.ErrUnauthorized
	}
	if u.DeletedAt != nil {
		return nil, domain.ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, domain.ErrUnauthorized
	}
	if t, _ := s.twofa.GetByUserID(ctx, u.ID); t != nil && t.IsEnrolled() {
		pt, err := s.tokens.MintPartial2FA(domain.Subject{Kind: domain.SubjectUser, UserID: u.ID})
		if err != nil {
			return nil, err
		}
		return &LoginResult{PartialToken: pt, TwoFARequired: true}, nil
	}
	sess, err := s.tokens.MintForUser(ctx, *u, ip, ua)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		Session:  sess,
		UserView: userView(u),
	}, nil
}

// LoginAdmin autentica admin. RequiresTwoFA (config no DB) = sempre PartialToken.
// Caso especial: admin com requires_2fa=true mas SEM enrollment ainda → PartialToken
// com claim enroll_needed pro UI mostrar wizard.
func (s *AuthService) LoginAdmin(ctx context.Context, email, password, ip, ua string) (*LoginResult, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || password == "" {
		return nil, domain.ErrInvalidInput
	}
	a, err := s.admins.GetByEmail(ctx, email)
	if err != nil || a == nil {
		return nil, domain.ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(password)); err != nil {
		return nil, domain.ErrUnauthorized
	}
	if a.RequiresTwoFA {
		// Mesmo se o admin não enroled ainda, exige passar pelo flow de enroll
		// antes de qualquer ação sensível — PartialToken segura ele lá.
		pt, err := s.tokens.MintPartial2FA(domain.Subject{Kind: domain.SubjectAdmin, AdminID: a.ID})
		if err != nil {
			return nil, err
		}
		return &LoginResult{PartialToken: pt, TwoFARequired: true}, nil
	}
	sess, err := s.tokens.MintForAdmin(ctx, *a, ip, ua)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		Session:   sess,
		AdminView: adminView(a),
	}, nil
}

// CompleteLogin2FA é chamado depois de /login com TwoFARequired. Recebe
// partial_token + código. Sucesso = MintedSession final.
func (s *AuthService) CompleteLogin2FA(ctx context.Context, partialToken, code, ip, ua string) (*LoginResult, error) {
	subj, err := s.tokens.ParsePartialToken(partialToken)
	if err != nil {
		return nil, err
	}
	if subj.Kind == domain.SubjectUser {
		if err := s.Verify2FA(ctx, subj, code); err != nil {
			return nil, err
		}
		u, err := s.users.GetByID(ctx, subj.UserID)
		if err != nil || u == nil {
			return nil, domain.ErrUnauthorized
		}
		sess, err := s.tokens.MintForUser(ctx, *u, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginResult{Session: sess, UserView: userView(u)}, nil
	}
	// Admin
	if err := s.Verify2FA(ctx, subj, code); err != nil {
		return nil, err
	}
	a, err := s.admins.GetByID(ctx, subj.AdminID)
	if err != nil || a == nil {
		return nil, domain.ErrUnauthorized
	}
	sess, err := s.tokens.MintForAdmin(ctx, *a, ip, ua)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Session: sess, AdminView: adminView(a)}, nil
}

// RegisterUser cria um user novo. Email único; phone OR telegram obrigatório
// (regra de negócio do projeto). Espelha core.user_auth_service.
func (s *AuthService) RegisterUser(ctx context.Context, email, password, name, phone, telegram, ip, ua string) (*LoginResult, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	name = strings.TrimSpace(name)
	phone = strings.TrimSpace(phone)
	telegram = strings.TrimSpace(telegram)
	if email == "" || password == "" {
		return nil, domain.ErrInvalidInput
	}
	if phone == "" && telegram == "" {
		return nil, domain.ErrInvalidInput
	}
	if existing, _ := s.users.GetByEmail(ctx, email); existing != nil {
		return nil, domain.ErrConflict
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	u := domain.User{
		ID:           uuid.New().String(),
		Email:        email,
		Name:         name,
		PasswordHash: hash,
		Phone:        phone,
		Telegram:     telegram,
	}
	if u.Name == "" {
		u.Name = email
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	sess, err := s.tokens.MintForUser(ctx, u, ip, ua)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Session: sess, UserView: userView(&u)}, nil
}

// ---- 2FA ----

type EnrollResult struct {
	SecretBase32 string
	OTPAuthURL   string
	BackupCodes  []string
}

func (s *AuthService) Enroll2FA(ctx context.Context, subj domain.Subject) (*EnrollResult, error) {
	// Label do account no Authenticator app.
	var label string
	if subj.Kind == domain.SubjectAdmin {
		a, err := s.admins.GetByID(ctx, subj.AdminID)
		if err != nil {
			return nil, err
		}
		label = a.Email + " (admin)"
	} else {
		u, err := s.users.GetByID(ctx, subj.UserID)
		if err != nil {
			return nil, err
		}
		label = u.Email
	}
	secretB32, otpURL, err := totp.Enroll(label)
	if err != nil {
		return nil, err
	}
	enc, err := totp.Encrypt(secretB32, s.encKey)
	if err != nil {
		return nil, err
	}
	codes, err := totp.GenerateBackupCodes(8)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		h, err := bcrypt.GenerateFromPassword([]byte(c), 10)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, string(h))
	}
	rec := domain.TwoFA{
		SubjectKind:     subj.Kind,
		UserID:          subj.UserID,
		AdminID:         subj.AdminID,
		EncryptedSecret: enc,
		BackupCodesHash: hashes,
	}
	if subj.Kind == domain.SubjectAdmin {
		if err := s.twofa.UpsertAdmin(ctx, rec); err != nil {
			return nil, err
		}
	} else {
		if err := s.twofa.UpsertUser(ctx, rec); err != nil {
			return nil, err
		}
	}
	return &EnrollResult{SecretBase32: secretB32, OTPAuthURL: otpURL, BackupCodes: codes}, nil
}

func (s *AuthService) Verify2FA(ctx context.Context, subj domain.Subject, code string) error {
	code = strings.TrimSpace(strings.ToUpper(code))
	if code == "" {
		return domain.ErrInvalidInput
	}
	var rec *domain.TwoFA
	var err error
	if subj.Kind == domain.SubjectAdmin {
		rec, err = s.twofa.GetByAdminID(ctx, subj.AdminID)
	} else {
		rec, err = s.twofa.GetByUserID(ctx, subj.UserID)
	}
	if err != nil || rec == nil {
		return domain.ErrTwoFANotEnrolled
	}
	wasEnrolled := rec.IsEnrolled()
	if isTOTPShape(code) {
		plain, err := totp.Decrypt(rec.EncryptedSecret, s.encKey)
		if err != nil {
			return err
		}
		if !totp.Verify(plain, code) {
			return domain.ErrInvalidTwoFACode
		}
	} else {
		// Backup code: itera os hashes, compara via bcrypt (constant time).
		found := ""
		for _, h := range rec.BackupCodesHash {
			if bcrypt.CompareHashAndPassword([]byte(h), []byte(code)) == nil {
				found = h
				break
			}
		}
		if found == "" {
			return domain.ErrInvalidTwoFACode
		}
		_ = s.twofa.ConsumeBackupCode(ctx, subj, found)
	}
	if !wasEnrolled {
		_ = s.twofa.MarkEnrolled(ctx, subj, time.Now().UTC())
	}
	return nil
}

func (s *AuthService) Disable2FA(ctx context.Context, subj domain.Subject) error {
	return s.twofa.Delete(ctx, subj)
}

// ---- Password reset ----

const passResetTTL = 1 * time.Hour

type PasswordResetIssued struct {
	TokenRaw string
}

// RequestPasswordReset cria um token (TTL 1h, single-use), grava hash no DB,
// e devolve o token bruto pro caller mandar por email.
// O caller NÃO loga se email existe (anti-enum).
func (s *AuthService) RequestPasswordReset(ctx context.Context, email, ip, ua string) (*PasswordResetIssued, *domain.User, *domain.Admin, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil, nil, nil, domain.ErrInvalidInput
	}
	// Tenta primeiro user; depois admin. Pra mesma email em ambos (raro), user prevalece.
	u, _ := s.users.GetByEmail(ctx, email)
	var a *domain.Admin
	if u == nil {
		a, _ = s.admins.GetByEmail(ctx, email)
	}
	if u == nil && a == nil {
		// Resposta success-mas-no-op pra anti-enum. Handler simula sucesso.
		return nil, nil, nil, nil
	}
	raw, hash := genResetToken()
	now := time.Now().UTC()
	rec := domain.PasswordReset{
		ID:                 uuid.New().String(),
		TokenHash:          hash,
		RequestedAt:        now,
		ExpiresAt:          now.Add(passResetTTL),
		RequestedIP:        ip,
		RequestedUserAgent: ua,
	}
	if u != nil {
		rec.UserID = strPtrAuth(u.ID)
	} else {
		rec.AdminID = strPtrAuth(a.ID)
	}
	if err := s.passResets.Create(ctx, rec); err != nil {
		return nil, nil, nil, err
	}
	return &PasswordResetIssued{TokenRaw: raw}, u, a, nil
}

// ConfirmPasswordReset valida o token bruto e troca a senha. Single-use:
// marca usado antes de atualizar. Revoga TODOS refresh tokens ativos do
// subject (force-logout em todos devices).
func (s *AuthService) ConfirmPasswordReset(ctx context.Context, tokenRaw, newPassword string) error {
	tokenRaw = strings.TrimSpace(tokenRaw)
	if tokenRaw == "" || newPassword == "" {
		return domain.ErrInvalidInput
	}
	hash := hashResetToken(tokenRaw)
	rec, err := s.passResets.GetByHash(ctx, hash)
	if err != nil {
		return domain.ErrUnauthorized
	}
	if rec.UsedAt != nil || time.Now().UTC().After(rec.ExpiresAt) {
		return domain.ErrUnauthorized
	}
	pwHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.passResets.MarkUsed(ctx, rec.ID); err != nil {
		return err
	}
	var subj domain.Subject
	if rec.UserID != nil {
		if err := s.users.UpdatePasswordHash(ctx, *rec.UserID, pwHash); err != nil {
			return err
		}
		subj = domain.Subject{Kind: domain.SubjectUser, UserID: *rec.UserID}
	} else if rec.AdminID != nil {
		if err := s.admins.UpdatePasswordHash(ctx, *rec.AdminID, pwHash); err != nil {
			return err
		}
		subj = domain.Subject{Kind: domain.SubjectAdmin, AdminID: *rec.AdminID}
	} else {
		return domain.ErrUnauthorized
	}
	// Force-logout — revoga todos refresh tokens vivos do subject.
	if err := s.tokens.refreshTokens.RevokeBySubject(ctx, subj); err != nil {
		return err
	}
	return nil
}

// ---- Helpers ----

func userView(u *domain.User) *UserView {
	if u == nil {
		return nil
	}
	return &UserView{ID: u.ID, Email: u.Email, Name: u.Name, Phone: u.Phone, Telegram: u.Telegram}
}

func adminView(a *domain.Admin) *AdminView {
	if a == nil {
		return nil
	}
	return &AdminView{ID: a.ID, Email: a.Email, Name: a.Name, Role: a.Role}
}

// isTOTPShape — 6 dígitos. Tudo o que não bate é tratado como backup code.
func isTOTPShape(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func genResetToken() (raw, hash string) {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	raw = hex.EncodeToString(b)
	hash = hashResetToken(raw)
	return
}

func hashResetToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func strPtrAuth(s string) *string { return &s }

// Sanity check pra evitar deadcode warnings.
var _ = errors.New
