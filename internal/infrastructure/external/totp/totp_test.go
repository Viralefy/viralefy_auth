package totp

import (
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	totppkg "github.com/pquerna/otp/totp"
)

// Vector check: Verify aceita o código gerado pra "agora" e rejeita códigos
// óbvios errados. Não revalidamos os RFC vectors completos (pquerna/otp já
// faz) — o foco aqui é o wrapper.

func TestEnroll_GeneratesUniqueSecrets(t *testing.T) {
	s1, _, err := Enroll("alice@viralefy.com")
	if err != nil {
		t.Fatalf("enroll1: %v", err)
	}
	s2, _, err := Enroll("alice@viralefy.com")
	if err != nil {
		t.Fatalf("enroll2: %v", err)
	}
	if s1 == s2 {
		t.Fatal("duas chamadas geraram o mesmo secret — entropia quebrada")
	}
	if !strings.HasPrefix(s1, "") || len(s1) < 16 {
		t.Fatalf("secret muito curto: len=%d", len(s1))
	}
}

func TestVerify_AcceptsCurrentWindowCode(t *testing.T) {
	secret, _, err := Enroll("bob@viralefy.com")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// Gera código pra "agora" usando o mesmo algoritmo subjacente.
	code, err := totppkg.GenerateCodeCustom(secret, time.Now(), totppkg.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	if !Verify(secret, code) {
		t.Fatalf("verify rejected own code: secret=%s code=%s", secret, code)
	}
}

func TestVerify_RejectsObviouslyWrong(t *testing.T) {
	secret, _, _ := Enroll("carol@viralefy.com")
	if Verify(secret, "000000") && Verify(secret, "111111") && Verify(secret, "999999") {
		t.Fatal("todos os trivials passaram — algo está aceitando qualquer coisa")
	}
}

func TestEncrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	plain := "JBSWY3DPEHPK3PXP" // valid base32
	enc, err := Encrypt(plain, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc == plain {
		t.Fatal("ciphertext == plaintext (something is no-op)")
	}
	dec, err := Decrypt(enc, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if dec != plain {
		t.Fatalf("roundtrip mismatch: got %q want %q", dec, plain)
	}
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	wrong := make([]byte, 32)
	io.ReadFull(rand.Reader, wrong)

	enc, _ := Encrypt("secret123", key)
	if _, err := Decrypt(enc, wrong); err == nil {
		t.Fatal("decrypt com key trocada deveria falhar (AES-GCM auth tag mismatch)")
	}
}

func TestEncrypt_RejectsWrongKeySize(t *testing.T) {
	short := make([]byte, 16) // 128 bits — não aceita
	if _, err := Encrypt("x", short); err == nil {
		t.Fatal("aceitou key de 16 bytes; deveria recusar")
	}
}

func TestGenerateBackupCodes_NRoundsCount(t *testing.T) {
	codes, err := GenerateBackupCodes(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 8 {
		t.Fatalf("got %d codes, want 8", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate backup code: %s", c)
		}
		seen[c] = true
		if len(c) < 8 {
			t.Fatalf("backup code muito curto: %s", c)
		}
		// base32 alphabet sem padding: A-Z + 2-7
		for _, r := range c {
			if !((r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7')) {
				t.Fatalf("char inválido em backup code %q: %c", c, r)
			}
		}
	}
}

func TestGenerateBackupCodes_DefaultsTo8WhenN_Le0(t *testing.T) {
	codes, _ := GenerateBackupCodes(0)
	if len(codes) != 8 {
		t.Fatalf("n=0 deve cair em default 8, got %d", len(codes))
	}
}

// Verify usa totp.Validate (sem skew explícito) que aplica skew=1 default.
// VerifyWithSkew com skew=0 deve rejeitar códigos não-atuais — mas não
// conseguimos forçar isso sem mock de time, deixamos como TODO para
// adicionar quando time provider for injetável.
