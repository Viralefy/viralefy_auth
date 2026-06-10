// Password utilities: bcrypt + senha aleatória legível.
//
// Mantém compatibilidade exata com o core (mesmo cost factor, mesmo charset)
// pra que hashes existentes em users.password_hash/admins.password_hash
// continuem válidos.
package application

import (
	"crypto/rand"
	"math/big"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// HashPassword wrappa bcrypt com cost padrão do projeto.
func HashPassword(pwd string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ComparePassword retorna nil se senha bate com o hash.
func ComparePassword(hash, pwd string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pwd))
}

// GeneratePassword cria senha aleatória forte e legível: 16 chars, ao
// menos 1 de cada classe (lower, upper, dígito, símbolo). Igual ao core
// (espelhado pra que admin gerar senha de novo admin no auth = mesma forma
// que via /admin/admins no core).
func GeneratePassword() string {
	const lower = "abcdefghjkmnpqrstuvwxyz"  // sem i,l,o,0,1 ambíguos
	const upper = "ABCDEFGHJKMNPQRSTUVWXYZ"
	const digits = "23456789"
	const symbols = "!@#$%&*?"
	const all = lower + upper + digits + symbols

	pick := func(set string) byte { return set[mustRand(len(set))] }

	chars := make([]byte, 16)
	chars[0] = pick(lower)
	chars[1] = pick(upper)
	chars[2] = pick(digits)
	chars[3] = pick(symbols)
	for i := 4; i < 16; i++ {
		chars[i] = all[mustRand(len(all))]
	}
	// Shuffle Fisher-Yates pra não revelar a posição dos garantidos.
	for i := len(chars) - 1; i > 0; i-- {
		j := mustRand(i + 1)
		chars[i], chars[j] = chars[j], chars[i]
	}
	return string(chars)
}

func mustRand(n int) int {
	nbig, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(nbig.Int64())
}
