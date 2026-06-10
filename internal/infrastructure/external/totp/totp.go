// Package totp encapsula geração e verificação de códigos TOTP (RFC 6238)
// + cifragem AES-256-GCM dos secrets em rest. Wrapping pquerna/otp pra:
//   - centralizar issuer/digits/period defaults
//   - prover crypto utilities pro repo (Encrypt/Decrypt secret)
//   - testabilidade: dep externo numa única interface
package totp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	issuer  = "Viralefy"
	digits  = otp.DigitsSix
	period  = 30
)

// Enroll gera um secret novo + URI otpauth:// pronta pra QR code. account
// identifica o usuário (admin email, user email) que aparece no app
// (Google Authenticator, Authy etc).
//
// Retorna (secretBase32, otpauthURI, error). Secret é a string base32 (sem
// padding) pra mostrar ao usuário como fallback caso QR não funcione.
func Enroll(account string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      period,
		Digits:      digits,
		Algorithm:   otp.AlgorithmSHA1, // compat máxima com authenticators
	})
	if err != nil {
		return "", "", fmt.Errorf("totp generate: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// Verify checa se o código bate com o secret. Tolerância ±1 janela (30s)
// pra clock skew suave do device.
func Verify(secretBase32, code string) bool {
	return totp.Validate(code, secretBase32)
}

// VerifyWithSkew aceita ±N janelas (cada janela = 30s). N=1 default em
// Verify. N=0 = strict.
func VerifyWithSkew(secretBase32, code string, skew uint) bool {
	ok, err := totp.ValidateCustom(code, secretBase32, time.Now(), totp.ValidateOpts{
		Period:    period,
		Skew:      skew,
		Digits:    digits,
		Algorithm: otp.AlgorithmSHA1,
	})
	return ok && err == nil
}

// =========================
// AES-256-GCM at-rest crypto
// =========================

// Encrypt cifra o secret base32 com AES-256-GCM. key tem que ter 32 bytes
// (256 bits). Retorna hex string (nonce ‖ ciphertext ‖ tag) pra guardar
// em coluna TEXT.
func Encrypt(plaintext string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("totp encrypt: key must be 32 bytes (got %d)", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ct), nil
}

// Decrypt reverte Encrypt. Erro = secret corrompido ou key trocada.
func Decrypt(ciphertextHex string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("totp decrypt: key must be 32 bytes (got %d)", len(key))
	}
	ct, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", fmt.Errorf("totp decrypt: hex: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(ct) < ns {
		return "", errors.New("totp decrypt: ciphertext too short")
	}
	nonce, body := ct[:ns], ct[ns:]
	pt, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return "", fmt.Errorf("totp decrypt: gcm: %w", err)
	}
	return string(pt), nil
}

// GenerateBackupCodes cria N códigos de 10 dígitos (base32 alfanumérico).
// 8 codes default — Google convention. Use-once: caller deve hash+store
// (bcrypt) e remover do slice após consumo.
func GenerateBackupCodes(n int) ([]string, error) {
	if n <= 0 {
		n = 8
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 6) // 6 bytes → 10 chars base32 sem padding
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return nil, err
		}
		out[i] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
	}
	return out, nil
}

