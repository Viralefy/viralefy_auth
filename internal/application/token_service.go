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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/Viralefy/viralefy_auth/internal/infrastructure/jwtkeys"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Identidade canônica do emissor e públicos esperados.
//
// `iss` (issuer) — quem assinou. Único no ecossistema: o próprio viralefy_auth.
// `aud` (audience) — quem PODE consumir. Tokens de access carregam todos os
// consumidores legítimos (`viralefy-api`, `viralefy-core`, `viralefy-payments`,
// `viralefy-sender`) e cada verificador valida com SEU próprio audience esperado.
// Partial tokens 2FA só circulam DENTRO do viralefy_auth → audience self.
//
// §14 dos padrões: JWT validado por inteiro inclui `iss` e `aud` contra
// allowlist explícita. Sem isso, token emitido p/ serviço A pode ser aceito
// por serviço B (confused deputy / cross-service replay).
const (
	JWTIssuer = "viralefy-auth"

	// AudiencePartial2FA — partial token só é consumido pelo próprio auth no
	// endpoint /login/2fa. Não deve ser aceito em lugar nenhum.
	AudiencePartial2FA = "viralefy-auth"

	// AudienceAPI, AudienceCore, AudiencePayments, AudienceSender — consumidores
	// internos do access token. O TokenService emite tokens válidos para todos
	// eles; cada verificador valida contra o SEU próprio nome.
	AudienceAPI      = "viralefy-api"
	AudienceCore     = "viralefy-core"
	AudiencePayments = "viralefy-payments"
	AudienceSender   = "viralefy-sender"
)

// AccessAudiences é a lista incluída no claim `aud` dos access tokens.
// Múltiplos audiences são permitidos pela RFC 7519 §4.1.3 (array de strings).
var AccessAudiences = []string{AudienceAPI, AudienceCore, AudiencePayments, AudienceSender}

// allowedAlgs — allowlist explícita §14. SEM isso, atacante pode tentar
// `alg=none` (token "válido" sem assinatura) ou forçar downgrade pra HMAC
// usando a chave pública RSA como secret. golang-jwt/v5 já trata `none`
// como SigningMethodNone (não casa com RSA/HMAC), mas a allowlist torna
// explícito e à prova de regressão.
var allowedAlgs = []string{"RS256", "HS256"}

type TokenService struct {
	priv            *rsa.PrivateKey
	kid             string
	legacyHS256     []byte
	accessTTL       time.Duration
	refreshTTL      time.Duration
	refreshTokens   domain.RefreshTokenRepository
	revokedJTIs     domain.RevokedJTIRepository
	// users/admins — usados por Refresh pra re-buscar role/email reais do
	// dono do refresh token. Sem isso, /refresh re-emitia com role genérico
	// ("admin", "user"), o que apaga o nível real (superadmin, manager,
	// support, viewer): perda de privilégio na melhor hipótese, escalada
	// disfarçada na pior. Construção opcional pra não quebrar testes legados
	// que instanciam TokenService só pra exercitar mint/verify; quando nil,
	// Refresh devolve ErrUnauthorized (fail-closed).
	users           domain.UserRepository
	admins          domain.AdminRepository
}

type TokenServiceConfig struct {
	PrivKey         *rsa.PrivateKey
	LegacyHS256     []byte // pode ser nil; quando set, valida HS256 antigos
	AccessTTL       time.Duration
	RefreshTTL      time.Duration
	RefreshTokens   domain.RefreshTokenRepository
	RevokedJTIs     domain.RevokedJTIRepository
	// Users/Admins — ver doc do struct TokenService. Injetados no wiring
	// (cmd/auth/main.go) ao lado dos demais repos.
	Users           domain.UserRepository
	Admins          domain.AdminRepository
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
		users:         cfg.Users,
		admins:        cfg.Admins,
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
//
// `iss` = viralefy-auth (§14); `aud` = viralefy-auth (consumido só pelo
// próprio serviço — não vaza pra api/core).
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
		"iss": JWTIssuer,
		"aud": AudiencePartial2FA,
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

	// §14 — claims `iss` e `aud` obrigatórios. `aud` lista todos os
	// consumidores legítimos; cada serviço valida contra o SEU nome.
	claims := jwt.MapClaims{
		"sub": c.Sub,
		"typ": c.Typ,
		"exp": c.Exp,
		"iat": c.Iat,
		"jti": c.Jti,
		"iss": JWTIssuer,
		"aud": AccessAudiences,
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

// VerifyAccess valida assinatura + exp + iss + aud + hot-set de revogação.
// Retorna claims tipadas ou um erro canônico (ErrTokenExpired,
// ErrTokenRevoked, ErrTokenMalformed, ErrUnauthorized).
//
// `expectedAudience` é o nome do CONSUMIDOR que está chamando este Verify
// (ex.: "viralefy-api"). Token sem esse audience na lista `aud` é rejeitado.
// Vazio = aceita qualquer audience da AccessAudiences (uso interno do auth
// p/ revogação/inspeção); em borda externa, SEMPRE passar o nome do consumer.
func (s *TokenService) VerifyAccess(ctx context.Context, raw, expectedAudience string) (*domain.AccessClaims, error) {
	if expectedAudience == "" {
		// Fallback inseguro só pra uso interno: aceita o primeiro audience
		// da lista (todos os tokens do auth carregam o conjunto inteiro).
		expectedAudience = AudienceAPI
	}
	t, err := s.parseDualSign(raw, expectedAudience)
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
	// Mint novo. ANTES era emitido com role/typ derivado só do Kind
	// (string(subj.Kind) virava "admin" pra TODO admin) — apagava o role
	// real (superadmin/manager/support/viewer) e o email. Resultado:
	// admin com role="superadmin" virava role="admin" no primeiro /refresh
	// e perdia privilégio (caminho feliz) ou — pior — passava a render
	// "admin" genérico onde a autorização downstream esperava role
	// específico, abrindo brecha de escalada/erro de gate.
	//
	// Correção (round 25, HIGH severity): re-buscar user/admin pelo ID
	// que veio com o refresh token e mintar com role/email REAIS. Se a
	// conta foi deletada/desativada entre issue e refresh, devolve
	// ErrUnauthorized — sessão revogada, sem mint.
	var subj domain.Subject
	if existing.UserID != nil {
		subj = domain.Subject{Kind: domain.SubjectUser, UserID: *existing.UserID}
	} else if existing.AdminID != nil {
		subj = domain.Subject{Kind: domain.SubjectAdmin, AdminID: *existing.AdminID}
	} else {
		// Refresh token órfão (sem user_id nem admin_id) — bug de dado,
		// nunca confiar. Fail-closed.
		return nil, domain.ErrUnauthorized
	}

	var claims domain.AccessClaims
	switch subj.Kind {
	case domain.SubjectAdmin:
		if s.admins == nil {
			// Wiring incompleto — fail-closed em vez de mintar com role default.
			return nil, domain.ErrUnauthorized
		}
		a, err := s.admins.GetByID(ctx, subj.AdminID)
		if err != nil || a == nil {
			// Admin deletado/desativado entre issue do refresh e este /refresh.
			// Trate como sessão revogada — não mint, não vaze diferença vs.
			// "não autorizado" pro caller.
			return nil, domain.ErrUnauthorized
		}
		claims = domain.AccessClaims{
			Sub:   a.ID,
			Typ:   "admin",
			Role:  a.Role,
			Email: a.Email,
		}
	case domain.SubjectUser:
		if s.users == nil {
			return nil, domain.ErrUnauthorized
		}
		u, err := s.users.GetByID(ctx, subj.UserID)
		if err != nil || u == nil || u.DeletedAt != nil {
			return nil, domain.ErrUnauthorized
		}
		claims = domain.AccessClaims{
			Sub:   u.ID,
			Typ:   "user",
			Role:  "user",
			Email: u.Email,
		}
	default:
		return nil, domain.ErrUnauthorized
	}

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
//
// Valida com audience = AudiencePartial2FA (self) — partial token NÃO
// é aceito como access token e vice-versa.
func (s *TokenService) ParsePartialToken(raw string) (domain.Subject, error) {
	t, err := s.parseDualSign(raw, AudiencePartial2FA)
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
//
// Hardening §14 (round 24 HIGH):
//   - WithValidMethods: allowlist explícita ("RS256","HS256"). Atacante NÃO
//     consegue forjar `alg=none` nem outras variantes (RS384/PS256/etc.)
//     mesmo se a keyfunc por engano retornar uma chave. Defesa em profundidade
//     além do switch de tipo.
//   - WithIssuer: rejeita token assinado pela MESMA chave mas com `iss`
//     diferente (ex.: outro serviço da casa que compartilhou a chave por
//     engano, ou pre-mudança onde `iss` não existia).
//   - WithAudience(expectedAudience): rejeita token cujo `aud` não inclui
//     o consumidor que está validando. Evita confused-deputy (token de
//     partial2FA aceito como access; token p/ payments aceito pelo core).
//   - WithExpirationRequired: token sem `exp` é rejeitado. golang-jwt/v5
//     aceita por default ausência de exp; aqui exigimos sempre.
//
// O switch interno na keyfunc continua sendo a primeira linha de defesa
// (retorna a chave certa por método e bloqueia HS256 quando legacy=off).
// A allowlist na Parser é a SEGUNDA linha — defense in depth.
func (s *TokenService) parseDualSign(raw, expectedAudience string) (*jwt.Token, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithIssuer(JWTIssuer),
		jwt.WithExpirationRequired(),
	}
	if expectedAudience != "" {
		opts = append(opts, jwt.WithAudience(expectedAudience))
	}
	parser := jwt.NewParser(opts...)

	t, err := parser.Parse(raw, func(t *jwt.Token) (interface{}, error) {
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
		// golang-jwt/v5 expõe erros canônicos via errors.Is — preferir isso
		// a strings.Contains, que é frágil a mudanças de mensagem.
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, domain.ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenMalformed),
			errors.Is(err, jwt.ErrTokenUnverifiable),
			errors.Is(err, jwt.ErrTokenSignatureInvalid),
			errors.Is(err, jwt.ErrTokenInvalidAudience),
			errors.Is(err, jwt.ErrTokenInvalidIssuer),
			errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
			return nil, domain.ErrTokenMalformed
		case strings.Contains(err.Error(), "unsupported"),
			strings.Contains(err.Error(), "signing method"):
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
