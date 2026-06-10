// Package jwtkeys carrega ou gera uma chave RSA privada usada para assinar
// JWTs com RS256. Fase 4.1 da migração HS256 → RS256 (dual-sign): novos
// tokens são assinados RS256, mas o validador aceita HS256 legado por uma
// janela de transição até que o operador desabilite explicitamente.
package jwtkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

// LoadOrGenerate retorna a chave RSA privada para assinar JWTs.
//
// Se path existir, é carregado como PEM PKCS#8 (preferido) ou PKCS#1.
// Caso contrário, gera uma nova chave 2048-bit, persiste em path com
// permissões 0600 (criando diretórios pai com 0700) e a retorna.
//
// Falhas de leitura/parse retornam erro (não silenciam pra evitar
// regerar chave e invalidar tokens emitidos).
func LoadOrGenerate(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("jwtkeys: empty path")
	}
	if data, err := os.ReadFile(path); err == nil {
		return parsePEM(data)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("jwtkeys: read %s: %w", path, err)
	}

	// Gera nova chave.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("jwtkeys: generate: %w", err)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("jwtkeys: mkdir %s: %w", dir, err)
		}
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("jwtkeys: marshal: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("jwtkeys: write %s: %w", path, err)
	}
	return key, nil
}

func parsePEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("jwtkeys: no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("jwtkeys: PKCS#8 key is not RSA")
		}
		return rk, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("jwtkeys: unsupported PEM key (need PKCS#1 or PKCS#8 RSA)")
}

// KeyID deriva um KID estável a partir do SHA-256 dos primeiros bytes do
// modulus público — usado pra distinguir tokens RS256 atuais de legados
// HS256 no validador.
func KeyID(priv *rsa.PrivateKey) string {
	if priv == nil {
		return ""
	}
	sum := sha256.Sum256(priv.PublicKey.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// PublicJWKS devolve a estrutura JWKS (RFC 7517) com a chave pública
// atual exposta em /.well-known/jwks.json. Clientes/serviços externos
// podem cachear a resposta — kid identifica a chave em rotações futuras.
func PublicJWKS(privKey *rsa.PrivateKey) (map[string]any, error) {
	if privKey == nil {
		return nil, fmt.Errorf("jwtkeys: nil private key")
	}
	pub := privKey.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": KeyID(privKey),
			"n":   n,
			"e":   e,
		}},
	}, nil
}
