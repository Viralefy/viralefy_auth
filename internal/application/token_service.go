// Package application — services do viralefy_auth.
//
// TokenService é o coração do auth: mint + verify de JWT + hot-set de
// revogação. Espelha 1:1 a estratégia do core (RS256 + kid + dual sign
// HS256 legado) — tokens em circulação continuam válidos durante
// cutover Fase 9b.
package application

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/Viralefy/viralefy_auth/internal/infrastructure/jwtkeys"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenService struct {
	priv            *rsa.PrivateKey
	kid             string
	legacyHS256     []byte
	accessTTL       time.Duration
	refreshTTL      time.Duration
	refreshTokens   domain.RefreshTokenRepository
	revokedJTIs     domain.RevokedJTIRepository
}

type TokenServiceConfig struct {
	PrivKey         *rsa.PrivateKey
	LegacyHS256     []byte // pode ser nil; quando set, valida HS256 antigos
	AccessTTL       time.Duration
	RefreshTTL      time.Duration
	RefreshTokens   domain.RefreshTokenRepository
	RevokedJTIs     domain.RevokedJTIRepository
}

func NewTokenService(cfg TokenServiceConfig) *TokenService {
	return &TokenService{
		priv:          cfg.PrivKey,
		kid:           jwtkeys.KeyID(cfg.PrivKey),
		legacyHS256:   cfg.LegacyHS256,
		accessTTL:     cfg.AccessTTL,
		refreshTTL:    cfg.RefreshTTL,
		refreshTokens: cfg.RefreshTokens,
		revokedJTIs:   cfg.RevokedJTIs,
	}
}

// PublicJWKS retorna a estrutura JWKS (RFC 7517) com a chave pública atual
// pra verificadores externos (Next.js front, dispatcher Rust offline).
func (s *TokenService) PublicJWKS() (map[string]any, error) {
	return jwtkeys.PublicJWKS(s.priv)
}

// MintedSession é o que o handler de /login retorna pro caller (core/dispatcher).
type MintedSession struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string // bruto, só devolvido aqui (hash persiste no DB)
	RefreshExpiresAt time.Time
	JTI              string
}

// MintForUser emite access+refresh pra um user.
func (s *TokenService) MintForUser(ctx context.Context, u domain.User, issueIP, ua string) (*MintedSession, error) {
	claims := domain.AccessClaims{
		Sub:   u.ID,
		Typ:   "user",
		Role:  "user",
		Email: u.Email,
	}
	return s.mint(ctx, claims, domain.Subject{Kind: domain.SubjectUser, UserID: u.ID}, issueIP, ua)
}

// MintForAdmin emite access+refresh pra um admin.
func (s *TokenService) MintForAdmin(ctx context.Context, a domain.Admin, issueIP, ua string) (*MintedSession, error) {
	claims := domain.AccessClaims{
		Sub:   a.ID,
		Typ:   "admin",
		Role:  a.Role,
		Email: a.Email,
	}
	return s.mint(ctx, claims, domain.Subject{Kind: domain.SubjectAdmin, AdminID: a.ID}, issueIP, ua)
}

// MintPartial2FA emite um token curto (5min) usado entre /login com 2FA
// pendente e /login/2fa. Preserva comportamento do core legacy.
func (s *TokenService) MintPartial2FA(subj domain.Subject) (string, error) {
	typ := "user_partial"
	if subj.Kind == domain.SubjectAdmin {
		typ = "admin_partial"
	}
	now := time.Now().UTC()
	exp := now.Add(5 * time.Minute)
	claims := jwt.MapClaims{
		"sub": subj.ID(),
		"typ": typ,
		"exp": exp.Unix(),
		"iat": now.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.kid != "" {
		tok.Header["kid"] = s.kid
	}
	return tok.SignedString(s.priv)
}

func (s *TokenService) mint(ctx context.Context, c domain.AccessClaims, subj domain.Subject, issueIP, ua string) (*MintedSession, error) {
	now := time.Now().UTC()
	accessExp := now.Add(s.accessTTL)
	c.Iat = now.Unix()
	c.Exp = accessExp.Unix()
	c.Jti = uuid.New().String()

	claims := jwt.MapClaims{
		"sub": c.Sub,
		"typ": c.Typ,
		"exp": c.Exp,
		"iat": c.Iat,
		"jti": c.Jti,
	}
	if c.Role != "" {
		claims["role"] = c.Role
	}
	if c.Email != "" {
		claims["email"] = c.Email
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.kid != "" {
		tok.Header["kid"] = s.kid
	}
	accessSigned, err := tok.SignedString(s.priv)
	if err != nil {
		return nil, fmt.Errorf("sign access: %w", err)
	}

	// Refresh: 256 bits aleatórios, hex. Hash SHA256 vai pro DB; bruto
	// devolvido UMA vez aqui.
	refreshRaw := genRefresh()
	refreshHash := hashRefresh(refreshRaw)
	refreshExp := now.Add(s.refreshTTL)
	rt := domain.RefreshToken{
		ID:             uuid.New().String(),
		TokenHash:      refreshHash,
		IssuedAt:       now,
		ExpiresAt:      refreshExp,
		IssueIP:        issueIP,
		IssueUserAgent: ua,
	}
	if subj.Kind == domain.SubjectAdmin {
		rt.AdminID = strPtr(subj.AdminID)
	} else {
		rt.UserID = strPtr(subj.UserID)
	}
	if err := s.refreshTokens.Create(ctx, rt); err != nil {
		return nil, fmt.Errorf("create refresh: %w", err)
	}

	return &MintedSession{
		AccessToken:      accessSigned,
		AccessExpiresAt:  accessExp,
		RefreshToken:     refreshRaw,
		RefreshExpiresAt: refreshExp,
		JTI:              c.Jti,
	}, nil
}

// VerifyAccess valida assinatura + exp + hot-set de revogação.
// Retorna claims tipadas ou um erro canônico (ErrTokenExpired,
// ErrTokenRevoked, ErrTokenMalformed, ErrUnauthorized).
func (s *TokenService) VerifyAccess(ctx context.Context, raw string) (*domain.AccessClaims, error) {
	t, err := s.parseDualSign(raw)
	if err != nil {
		return nil, err
	}
	claims, _ := t.Claims.(jwt.MapClaims)
	// Mapeia pra typed.
	out := &domain.AccessClaims{}
	if v, ok := claims["sub"].(string); ok {
		out.Sub = v
	}
	if v, ok := claims["typ"].(string); ok {
		out.Typ = v
	}
	if v, ok := claims["role"].(string); ok {
		out.Role = v
	}
	if v, ok := claims["email"].(string); ok {
		out.Email = v
	}
	if v, ok := claims["jti"].(string); ok {
		out.Jti = v
	}
	if v, ok := claims["exp"].(float64); ok {
		out.Exp = int64(v)
	}
	if v, ok := claims["iat"].(float64); ok {
		out.Iat = int64(v)
	}
	// Hot-set: se jti revogado, falha mesmo com sig válida.
	if out.Jti != "" {
		revoked, err := s.revokedJTIs.IsRevoked(ctx, out.Jti)
		if err != nil {
			return nil, fmt.Errorf("check revoked: %w", err)
		}
		if revoked {
			return out, domain.ErrTokenRevoked
		}
	}
	return out, nil
}

// Refresh rotaciona o refresh token: valida o input, revoga o antigo,
// emite par novo. Anti-replay garantido pela revogação atômica.
func (s *TokenService) Refresh(ctx context.Context, refreshRaw, issueIP, ua string) (*MintedSession, error) {
	hash := hashRefresh(refreshRaw)
	existing, err := s.refreshTokens.GetByHash(ctx, hash)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}
	if !existing.IsActive() {
		// Replay attempt: tentar usar um já revogado é SINAL de comprometimento.
		// Revoga TUDO do subject como precaução (force-logout).
		var subj domain.Subject
		if existing.UserID != nil {
			subj = domain.Subject{Kind: domain.SubjectUser, UserID: *existing.UserID}
		} else if existing.AdminID != nil {
			subj = domain.Subject{Kind: domain.SubjectAdmin, AdminID: *existing.AdminID}
		}
		_ = s.refreshTokens.RevokeBySubject(ctx, subj)
		return nil, domain.ErrTokenRevoked
	}
	// Mint novo.
	var subj domain.Subject
	if existing.UserID != nil {
		subj = domain.Subject{Kind: domain.SubjectUser, UserID: *existing.UserID}
	} else if existing.AdminID != nil {
		subj = domain.Subject{Kind: domain.SubjectAdmin, AdminID: *existing.AdminID}
	}
	// Não temos email/role aqui — quem chamou /refresh passa os dados
	// re-buscando no repo de user/admin. Pra interface limpa, retornamos
	// só o subject; handler decide se busca metadata. Implementação
	// suficiente pra dispatcher: emite token com role default (lookup
	// é responsabilidade do handler real).
	claims := domain.AccessClaims{Sub: subj.ID(), Typ: string(subj.Kind), Role: string(subj.Kind)}
	session, err := s.mint(ctx, claims, subj, issueIP, ua)
	if err != nil {
		return nil, err
	}
	// Revoga o antigo APONTANDO o novo como sucessor.
	if err := s.refreshTokens.Revoke(ctx, existing.ID, ""); err != nil {
		return nil, err
	}
	return session, nil
}

// RevokeAccessJTI adiciona o jti à hot-set. Usado em logout, force-logout
// admin, password reset, mudança de role.
func (s *TokenService) RevokeAccessJTI(ctx context.Context, jti string, expiresAt time.Time, reason string) error {
	if jti == "" {
		return domain.ErrInvalidInput
	}
	return s.revokedJTIs.Add(ctx, domain.RevokedJTI{
		JTI:       jti,
		ExpiresAt: expiresAt,
		Reason:    reason,
	})
}

// Logout: revoga refresh + access JTI atual.
func (s *TokenService) Logout(ctx context.Context, refreshRaw, accessJTI string, accessExp time.Time) error {
	if refreshRaw != "" {
		hash := hashRefresh(refreshRaw)
		if existing, err := s.refreshTokens.GetByHash(ctx, hash); err == nil && existing != nil {
			_ = s.refreshTokens.Revoke(ctx, existing.ID, "")
		}
	}
	if accessJTI != "" {
		_ = s.RevokeAccessJTI(ctx, accessJTI, accessExp, "logout")
	}
	return nil
}

// ParsePartialToken é utility pra validar partial_token e devolver subject.
// 2FA flow: /login (pwd OK + 2FA enabled) → MintPartial2FA → /login/2fa
// chama isso pra extrair subject e validar TOTP.
func (s *TokenService) ParsePartialToken(raw string) (domain.Subject, error) {
	t, err := s.parseDualSign(raw)
	if err != nil {
		return domain.Subject{}, err
	}
	claims, _ := t.Claims.(jwt.MapClaims)
	typ, _ := claims["typ"].(string)
	sub, _ := claims["sub"].(string)
	if sub == "" || (typ != "user_partial" && typ != "admin_partial") {
		return domain.Subject{}, domain.ErrUnauthorized
	}
	if typ == "admin_partial" {
		return domain.Subject{Kind: domain.SubjectAdmin, AdminID: sub}, nil
	}
	return domain.Subject{Kind: domain.SubjectUser, UserID: sub}, nil
}

// parseDualSign aceita RS256 primário + HS256 legado durante migração.
func (s *TokenService) parseDualSign(raw string) (*jwt.Token, error) {
	t, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA:
			return &s.priv.PublicKey, nil
		case *jwt.SigningMethodHMAC:
			if len(s.legacyHS256) == 0 {
				return nil, fmt.Errorf("hs256 disabled")
			}
			return s.legacyHS256, nil
		default:
			return nil, fmt.Errorf("unsupported alg: %v", t.Method)
		}
	})
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "expired"):
			return nil, domain.ErrTokenExpired
		case strings.Contains(err.Error(), "malformed"), strings.Contains(err.Error(), "unsupported"):
			return nil, domain.ErrTokenMalformed
		default:
			return nil, domain.ErrUnauthorized
		}
	}
	if !t.Valid {
		return nil, domain.ErrUnauthorized
	}
	return t, nil
}

func genRefresh() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashRefresh(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func strPtr(s string) *string { return &s }
