package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Viralefy/viralefy_auth/internal/domain"
)

// decodeErrorBody le o body do recorder como errorBody.
func decodeErrorBody(t *testing.T, rec *httptest.ResponseRecorder) errorBody {
	t.Helper()
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return body
}

// Round 28/29: RegisterUser passou a wrap ErrConflict com mensagem útil:
//
//	fmt.Errorf("email already registered: %w", domain.ErrConflict)
//
// O response.go faz strings.TrimSuffix(": conflict") pra entregar pro
// frontend uma mensagem limpa "email already registered" — o ApiError
// no frontend usa code+message pra mostrar CTA "Sign in / Recover".
//
// Estes testes trancam o contrato.

func TestWriteError_BareConflict_KeepsLegacyMessage(t *testing.T) {
	rec := httptest.NewRecorder()

	writeError(rec, domain.ErrConflict)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
	body := decodeErrorBody(t, rec)
	if body.Error.Code != "CONFLICT" {
		t.Errorf("expected CONFLICT, got %q", body.Error.Code)
	}
	if body.Error.Message != "conflict" {
		t.Errorf("expected bare 'conflict' for unwrapped sentinel, got %q", body.Error.Message)
	}
	if body.Error.TraceID == "" {
		t.Errorf("trace_id ausente")
	}
}

func TestWriteError_WrappedConflict_ReturnsCleanMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	// RegisterUser path em auth_service.go:248
	wrapped := fmt.Errorf("email already registered: %w", domain.ErrConflict)

	writeError(rec, wrapped)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
	body := decodeErrorBody(t, rec)
	if body.Error.Code != "CONFLICT" {
		t.Errorf("expected CONFLICT, got %q", body.Error.Code)
	}
	// Contrato com o frontend: lib/api.ts ApiError lê este campo.
	// Mudança aqui quebra a UX do round 29.
	if body.Error.Message != "email already registered" {
		t.Errorf("expected clean message 'email already registered', got %q", body.Error.Message)
	}
}

func TestWriteError_DeeplyWrappedConflict_NoSentinelLeak(t *testing.T) {
	rec := httptest.NewRecorder()
	inner := fmt.Errorf("email already registered: %w", domain.ErrConflict)
	outer := fmt.Errorf("auth_service: %w", inner)

	writeError(rec, outer)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
	body := decodeErrorBody(t, rec)
	if strings.HasSuffix(body.Error.Message, ": conflict") {
		t.Errorf("sufixo ': conflict' vazou: %q", body.Error.Message)
	}
}

func TestWriteError_Unauthorized_FixedMessage(t *testing.T) {
	// Anti-enum: a mensagem é fixa "unauthorized", não vem do err.Error()
	// (preserva indistinguibilidade entre "email não existe" e "senha errada").
	rec := httptest.NewRecorder()

	writeError(rec, fmt.Errorf("user not found: %w", domain.ErrUnauthorized))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	body := decodeErrorBody(t, rec)
	if body.Error.Code != "UNAUTHORIZED" {
		t.Errorf("expected UNAUTHORIZED, got %q", body.Error.Code)
	}
	if body.Error.Message != "unauthorized" {
		t.Errorf("anti-enum quebrado — message vazou contexto: %q", body.Error.Message)
	}
}
