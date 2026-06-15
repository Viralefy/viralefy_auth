// Round 25 HIGH fix: o Refresh ANTES re-emitia access tokens com role
// derivada do SubjectKind (string(subj.Kind) → "admin" pra TODO admin),
// apagando o role REAL (superadmin/manager/support/viewer) e o email
// do dono do refresh token. Este teste cobre:
//
//  1. Admin com role específico → /refresh → novo access_token PRESERVA
//     o role real (superadmin) e o email — não vira "admin" genérico.
//  2. Admin deletado/desativado ENTRE issue e refresh → ErrUnauthorized
//     (sessão revogada), sem mintar token novo.
//  3. User não-deletado → /refresh → novo token com role="user" + email real.
//  4. User soft-deleted entre issue e refresh → ErrUnauthorized.
//
// Os mocks são in-memory, sem DB — testam EXATAMENTE o branch que o bug
// pisava: o mint final no Refresh. Pra detectar o bug velho, asseramos
// claims do JWT emitido (não o input).
package application

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Viralefy/viralefy_auth/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

// ---- Mocks de repositório (apenas o necessário pro Refresh) ----

type fakeUserRepo struct {
	users map[string]*domain.User
}

func (r *fakeUserRepo) GetByID(_ context.Context, id string) (*domain.User, error) {
	if u, ok := r.users[id]; ok {
		return u, nil
	}
	return nil, errors.New("not found")
}
func (r *fakeUserRepo) GetByEmail(_ context.Context, _ string) (*domain.User, error) {
	return nil, errors.New("not impl")
}
func (r *fakeUserRepo) Create(_ context.Context, _ domain.User) error    { return nil }
func (r *fakeUserRepo) UpdatePasswordHash(_ context.Context, _, _ string) error { return nil }

type fakeAdminRepo struct {
	admins map[string]*domain.Admin
}

func (r *fakeAdminRepo) GetByID(_ context.Context, id string) (*domain.Admin, error) {
	if a, ok := r.admins[id]; ok {
		return a, nil
	}
	// Espelha o que o repo postgres devolve quando não acha: nil + erro.
	return nil, errors.New("not found")
}
func (r *fakeAdminRepo) GetByEmail(_ context.Context, _ string) (*domain.Admin, error) {
	return nil, errors.New("not impl")
}
func (r *fakeAdminRepo) UpdatePasswordHash(_ context.Context, _, _ string) error { return nil }

type fakeRefreshRepo struct {
	byHash map[string]*domain.RefreshToken
}

func (r *fakeRefreshRepo) Create(_ context.Context, t domain.RefreshToken) error {
	if r.byHash == nil {
		r.byHash = map[string]*domain.RefreshToken{}
	}
	rt := t
	r.byHash[t.TokenHash] = &rt
	return nil
}
func (r *fakeRefreshRepo) GetByHash(_ context.Context, hash string) (*domain.RefreshToken, error) {
	if rt, ok := r.byHash[hash]; ok {
		return rt, nil
	}
	return nil, errors.New("not found")
}
func (r *fakeRefreshRepo) Revoke(_ context.Context, id, _ string) error {
	for _, rt := range r.byHash {
		if rt.ID == id {
			now := time.Now().UTC()
			rt.RevokedAt = &now
			return nil
		}
	}
	return nil
}
func (r *fakeRefreshRepo) RevokeBySubject(_ context.Context, subj domain.Subject) error {
	for _, rt := range r.byHash {
		if (subj.Kind == domain.SubjectAdmin && rt.AdminID != nil && *rt.AdminID == subj.AdminID) ||
			(subj.Kind == domain.SubjectUser && rt.UserID != nil && *rt.UserID == subj.UserID) {
			now := time.Now().UTC()
			rt.RevokedAt = &now
		}
	}
	return nil
}

type fakeRevokedJTIRepo struct{}

func (r *fakeRevokedJTIRepo) Add(_ context.Context, _ domain.RevokedJTI) error { return nil }
func (r *fakeRevokedJTIRepo) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (r *fakeRevokedJTIRepo) ListActive(_ context.Context) ([]domain.RevokedJTI, error) {
	return nil, nil
}

// ---- Helpers ----

func newTestTokenService(t *testing.T, users domain.UserRepository, admins domain.AdminRepository) (*TokenService, *fakeRefreshRepo) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	rr := &fakeRefreshRepo{byHash: map[string]*domain.RefreshToken{}}
	svc := NewTokenService(TokenServiceConfig{
		PrivKey:       priv,
		AccessTTL:     15 * time.Minute,
		RefreshTTL:    24 * time.Hour,
		RefreshTokens: rr,
		RevokedJTIs:   &fakeRevokedJTIRepo{},
		Users:         users,
		Admins:        admins,
	})
	return svc, rr
}

// parseAccessClaimsNoVerify lê os claims do access token SEM verificar
// assinatura — testes que checam role/email só precisam do payload.
// (Pra evitar acoplar o teste à API exata de VerifyAccess do repo, que
// pode ou não receber audience.)
func parseAccessClaimsNoVerify(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed jwt: %d parts", len(parts))
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	tok, _, err := parser.ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type")
	}
	return c
}

// ---- Tests ----

func TestRefresh_PreservesAdminRealRole(t *testing.T) {
	admin := &domain.Admin{
		ID:    "admin-1",
		Email: "boss@example.test",
		Role:  "superadmin",
	}
	users := &fakeUserRepo{users: map[string]*domain.User{}}
	admins := &fakeAdminRepo{admins: map[string]*domain.Admin{admin.ID: admin}}
	svc, _ := newTestTokenService(t, users, admins)

	// 1) Mint inicial — emula login completo de superadmin.
	first, err := svc.MintForAdmin(context.Background(), *admin, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("MintForAdmin: %v", err)
	}
	firstClaims := parseAccessClaimsNoVerify(t, first.AccessToken)
	if firstClaims["role"] != "superadmin" {
		t.Fatalf("initial role = %v, want superadmin", firstClaims["role"])
	}

	// 2) Refresh — o bug velho re-emitia role="admin" (genérico).
	refreshed, err := svc.Refresh(context.Background(), first.RefreshToken, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	refreshedClaims := parseAccessClaimsNoVerify(t, refreshed.AccessToken)

	// PISO INEGOCIÁVEL: role real preservado.
	if got := refreshedClaims["role"]; got != "superadmin" {
		t.Errorf("refreshed role = %v, want superadmin (bug velho re-emitia role default genérico)", got)
	}
	// Email também tem que voltar.
	if got := refreshedClaims["email"]; got != admin.Email {
		t.Errorf("refreshed email = %v, want %q", got, admin.Email)
	}
	// Sub tem que ser o admin ID.
	if got := refreshedClaims["sub"]; got != admin.ID {
		t.Errorf("refreshed sub = %v, want %q", got, admin.ID)
	}
	if got := refreshedClaims["typ"]; got != "admin" {
		t.Errorf("refreshed typ = %v, want admin", got)
	}
}

func TestRefresh_AdminDeletedBetweenIssueAndRefresh_ReturnsUnauthorized(t *testing.T) {
	admin := &domain.Admin{
		ID:    "admin-2",
		Email: "ghost@example.test",
		Role:  "manager",
	}
	users := &fakeUserRepo{users: map[string]*domain.User{}}
	admins := &fakeAdminRepo{admins: map[string]*domain.Admin{admin.ID: admin}}
	svc, _ := newTestTokenService(t, users, admins)

	first, err := svc.MintForAdmin(context.Background(), *admin, "10.0.0.1", "ua")
	if err != nil {
		t.Fatalf("MintForAdmin: %v", err)
	}

	// Simula admin deletado (remove do repo) — força-logout server-side
	// deve ter revogado refresh, mas testamos o cenário em que o gap entre
	// delete e revogação permitiu o refresh chegar primeiro.
	delete(admins.admins, admin.ID)

	_, err = svc.Refresh(context.Background(), first.RefreshToken, "10.0.0.1", "ua")
	if err == nil {
		t.Fatalf("expected error, got nil (deveria recusar refresh quando admin não existe mais)")
	}
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}

func TestRefresh_UserPreservesEmail(t *testing.T) {
	u := &domain.User{
		ID:    "user-1",
		Email: "alice@example.test",
		Name:  "Alice",
	}
	users := &fakeUserRepo{users: map[string]*domain.User{u.ID: u}}
	admins := &fakeAdminRepo{admins: map[string]*domain.Admin{}}
	svc, _ := newTestTokenService(t, users, admins)

	first, err := svc.MintForUser(context.Background(), *u, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("MintForUser: %v", err)
	}

	refreshed, err := svc.Refresh(context.Background(), first.RefreshToken, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	c := parseAccessClaimsNoVerify(t, refreshed.AccessToken)
	if got := c["role"]; got != "user" {
		t.Errorf("refreshed role = %v, want user", got)
	}
	if got := c["email"]; got != u.Email {
		t.Errorf("refreshed email = %v, want %q", got, u.Email)
	}
	if got := c["typ"]; got != "user" {
		t.Errorf("refreshed typ = %v, want user", got)
	}
}

func TestRefresh_UserSoftDeleted_ReturnsUnauthorized(t *testing.T) {
	now := time.Now().UTC()
	u := &domain.User{
		ID:    "user-2",
		Email: "deleted@example.test",
	}
	users := &fakeUserRepo{users: map[string]*domain.User{u.ID: u}}
	admins := &fakeAdminRepo{admins: map[string]*domain.Admin{}}
	svc, _ := newTestTokenService(t, users, admins)

	first, err := svc.MintForUser(context.Background(), *u, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("MintForUser: %v", err)
	}

	// Soft-delete entre issue e refresh.
	u.DeletedAt = &now

	_, err = svc.Refresh(context.Background(), first.RefreshToken, "127.0.0.1", "ua")
	if err == nil {
		t.Fatalf("expected error, got nil (user soft-deleted deveria ter sessão revogada)")
	}
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}
