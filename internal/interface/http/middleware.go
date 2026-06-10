package http

import (
	"crypto/subtle"
	"net/http"
)

// InternalTokenAuth valida X-Internal-Token em todo request /internal/v1/*.
// O secret é compartilhado com core/dispatcher via env INTERNAL_SHARED_SECRET.
// Comparison constant-time anti timing leak.
func InternalTokenAuth(secret string) func(http.Handler) http.Handler {
	expected := []byte(secret)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := []byte(r.Header.Get("X-Internal-Token"))
			if len(expected) == 0 || subtle.ConstantTimeCompare(expected, got) != 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":"UNAUTHORIZED","message":"invalid internal token"}}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extrai IP do request — X-Real-IP > X-Forwarded-For first > RemoteAddr.
// Caddy/dispatcher já populam X-Real-IP nos requests internos.
func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		// Pode ter lista; o primeiro é o IP real do cliente.
		for i, c := range v {
			if c == ',' {
				return v[:i]
			}
		}
		return v
	}
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}
