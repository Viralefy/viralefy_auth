// Round 25 HIGH fix (Track AA): hardening do parseDualSign em
// token_service.go — JWT agora é validado por INTEIRO em conformidade
// com §14 dos padrões da casa:
//
//   - alg em allowlist explícita ({RS256, HS256}) via jwt.WithValidMethods.
//     Token com alg=none, RS384, PS256, etc. → rejeitado.
//   - `iss` obrigatório e igual a JWTIssuer ("viralefy-auth").
//   - `aud` deve conter o consumer que está validando (ex.: "viralefy-api").
//   - `exp` obrigatório (jwt.WithExpirationRequired). Token sem exp → rejeitado.
//
// Os testes deste arquivo reutilizam os mocks definidos em
// refresh_role_test.go (mesmo package). Cobrem 5 cenários:
//
//  1. Token válido (mint padrão) → aceito.
//  2. Token com alg=none → ErrTokenMalformed.
//  3. Token com `iss` errado → ErrTokenMalformed.
//  4. Token com `aud` que não bate com o consumer → ErrTokenMalformed.
//  5. Token sem `exp` → ErrTokenMalformed.
package application

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

// newHardeningSvc constrói TokenService minimal (mesmas fakes do
// refresh_role_test.go) com chave RSA fresca.
func newHardeningSvc(t *testing.T) (*TokenService, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	svc := NewTokenService(TokenServiceConfig{
		PrivKey:       priv,
		AccessTTL:     15 * time.Minute,
		RefreshTTL:    24 * time.Hour,
		RefreshTokens: &fakeRefreshRepo{byHash: map[string]*domain.RefreshToken{}},
		RevokedJTIs:   &fakeRevokedJTIRepo{},
		Users:         &fakeUserRepo{users: map[string]*domain.User{}},
		Admins:        &fakeAdminRepo{admins: map[string]*domain.Admin{}},
	})
	return svc, priv
}

// signRS256 mints um token assinado pela chave RSA com claims arbitrários.
// Usado pelos testes pra construir cenários hostis (iss/aud/exp errados).
func signRS256(t *testing.T, priv *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// ---- Tests ----

// 1. Caminho feliz: token mintado pelo próprio service é aceito pelo
//    VerifyAccess quando o consumer informa o audience certo.
func TestVerifyAccess_ValidToken_Accepted(t *testing.T) {
	svc, _ := newHardeningSvc(t)
	u := domain.User{ID: "user-ok", Email: "ok@example.test"}
	sess, err := svc.MintForUser(context.Background(), u, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("MintForUser: %v", err)
	}
	claims, err := svc.VerifyAccess(context.Background(), sess.AccessToken, AudienceAPI)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if claims.Sub != u.ID {
		t.Errorf("sub = %q, want %q", claims.Sub, u.ID)
	}
}

// 2. alg=none — atacante remove a assinatura. golang-jwt/v5 já rejeita
//    none via SigningMethodNone, mas a allowlist explícita garante que
//    isso continua valendo mesmo se a keyfunc for alterada no futuro.
func TestVerifyAccess_AlgNone_Rejected(t *testing.T) {
	svc, _ := newHardeningSvc(t)
	// jwt.UnsafeAllowNoneSignatureType é o sentinel exigido pela lib pra
	// permitir mint com alg=none (caso explícito de atacante).
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "evil",
		"iss": JWTIssuer,
		"aud": AccessAudiences,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	_, err = svc.VerifyAccess(context.Background(), raw, AudienceAPI)
	if err == nil {
		t.Fatalf("expected rejection of alg=none, got nil")
	}
	if !errors.Is(err, domain.ErrTokenMalformed) && !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("err = %v, want ErrTokenMalformed or ErrUnauthorized", err)
	}
}

// 3. iss errado — token assinado com a chave certa mas afirmando ser de
//    outro emissor. Cenário: chave compartilhada entre serviços ou
//    rotação parcial. Sem checagem de iss, esse token passaria.
func TestVerifyAccess_WrongIssuer_Rejected(t *testing.T) {
	svc, priv := newHardeningSvc(t)
	raw := signRS256(t, priv, jwt.MapClaims{
		"sub": "x",
		"iss": "atacante-fake-issuer",
		"aud": AccessAudiences,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	_, err := svc.VerifyAccess(context.Background(), raw, AudienceAPI)
	if err == nil {
		t.Fatalf("expected rejection for wrong iss, got nil")
	}
	if !errors.Is(err, domain.ErrTokenMalformed) {
		t.Errorf("err = %v, want ErrTokenMalformed (iss mismatch)", err)
	}
}

// 4. aud errado — token emitido pra outro consumer (ex.: tinha aud
//    "viralefy-payments" e estamos validando como "viralefy-api"). Mesma
//    chave, mesmo iss, mas audience diferente → rejeitar.
func TestVerifyAccess_WrongAudience_Rejected(t *testing.T) {
	svc, priv := newHardeningSvc(t)
	raw := signRS256(t, priv, jwt.MapClaims{
		"sub": "x",
		"iss": JWTIssuer,
		"aud": "some-other-service",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	_, err := svc.VerifyAccess(context.Background(), raw, AudienceAPI)
	if err == nil {
		t.Fatalf("expected rejection for wrong aud, got nil")
	}
	if !errors.Is(err, domain.ErrTokenMalformed) {
		t.Errorf("err = %v, want ErrTokenMalformed (aud mismatch)", err)
	}
}

// 5. Sem exp — golang-jwt/v5 por default aceita token sem exp (claim
//    opcional na spec). Aqui exigimos via WithExpirationRequired.
//    Sem essa flag, token sem exp = token eterno.
func TestVerifyAccess_MissingExp_Rejected(t *testing.T) {
	svc, priv := newHardeningSvc(t)
	raw := signRS256(t, priv, jwt.MapClaims{
		"sub": "x",
		"iss": JWTIssuer,
		"aud": AccessAudiences,
		"iat": time.Now().Unix(),
		// SEM exp.
	})
	_, err := svc.VerifyAccess(context.Background(), raw, AudienceAPI)
	if err == nil {
		t.Fatalf("expected rejection for missing exp, got nil")
	}
	if !errors.Is(err, domain.ErrTokenMalformed) {
		t.Errorf("err = %v, want ErrTokenMalformed (exp missing)", err)
	}
}

// 6 (bônus). Partial token (2FA) emitido pelo MintPartial2FA tem aud
//    "viralefy-auth" — NÃO pode ser aceito como access token validado
//    pra "viralefy-api". Garante isolamento entre os dois tipos de token.
func TestVerifyAccess_RejectsPartial2FAToken(t *testing.T) {
	svc, _ := newHardeningSvc(t)
	subj := domain.Subject{Kind: domain.SubjectUser, UserID: "u1"}
	partial, err := svc.MintPartial2FA(subj)
	if err != nil {
		t.Fatalf("MintPartial2FA: %v", err)
	}
	_, err = svc.VerifyAccess(context.Background(), partial, AudienceAPI)
	if err == nil {
		t.Fatalf("expected rejection — partial 2FA token não é access token")
	}
	// E reciprocamente: ParsePartialToken aceita o partial.
	got, err := svc.ParsePartialToken(partial)
	if err != nil {
		t.Fatalf("ParsePartialToken: %v", err)
	}
	if got.UserID != subj.UserID {
		t.Errorf("subj = %+v, want UserID=%q", got, subj.UserID)
	}
}
