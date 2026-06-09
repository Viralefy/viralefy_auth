# viralefy_auth

Serviço de identidade do Viralefy. Mint + verify de JWT, login/register/refresh, 2FA TOTP, password reset, audit de eventos de auth, hot-set de revogação no Postgres.

Status: **scaffold inicial (2026-06-09)**. Health check no ar, handlers reais entram nos próximos commits da PHASE-9 §4.2 (Auth extraction).

## Princípios

- **Superfície mínima**: sem business logic além de identidade. Auth NÃO conhece planos, pedidos, gateways.
- **Loopback only**: bind em `127.0.0.1:8083`. Não exposto na internet — Caddy + dispatcher fazem proxy seletivo.
- **`INTERNAL_SHARED_SECRET`**: todo request entre `viralefy_api`/`viralefy_core` ↔ `viralefy_auth` carrega o header `X-Internal-Token`.
- **Log estruturado**: todas tentativas de auth (sucesso e falha) com IP, UA, request-id pra correlação.
- **Hot-set de revogação no Postgres** (tabela `revoked_jtis`): NÃO memória — sobrevive a restart e cluster.
- **Chave RS256 mestre** carregada de `/etc/viralefy/keys/jwt-rs256.pem`. Durante cutover Fase 9b (≤14 dias corridos), compartilhada com `viralefy_core`. Após cutover, auth é único mint.

## Plano arquitetural

Detalhes em [`viralefy_archive/PHASE-9-ARCHITECTURE.md`](https://github.com/Viralefy/viralefy_archive/blob/main/PHASE-9-ARCHITECTURE.md).

## Endpoints planejados

Loopback `/internal/v1/*` (chamados por `viralefy_api` ou `viralefy_core`):

```
POST   /internal/v1/login                  body: {email, password, twofa_code?}
POST   /internal/v1/register               body: {email, password, name, ...}
POST   /internal/v1/refresh                body: {refresh_token}
POST   /internal/v1/logout                 body: {refresh_token}
POST   /internal/v1/password/reset/request body: {email}
POST   /internal/v1/password/reset/confirm body: {token, new_password}
POST   /internal/v1/twofa/enroll           header: Bearer
POST   /internal/v1/twofa/verify           header: Bearer  body: {code}
POST   /internal/v1/twofa/disable          header: Bearer  body: {code}
GET    /internal/v1/twofa/backup_codes     header: Bearer
POST   /internal/v1/token/verify           body: {token}  → {valid, claims, error?}
POST   /internal/v1/token/revoke           body: {jti}    (gera row em revoked_jtis)
GET    /internal/v1/jwks                   public JWKS (proxy do .well-known)
GET    /internal/v1/health
GET    /internal/v1/ready
```

## Rodar local

```bash
export DATABASE_URL=postgres://viralefy:viralefy@localhost:5432/viralefy?sslmode=disable
export INTERNAL_SHARED_SECRET=$(openssl rand -hex 32)
export TWOFA_ENCRYPTION_KEY=$(openssl rand -hex 32)
export JWT_PRIVATE_KEY_PATH=/etc/viralefy/jwt-rs256.pem
go run ./cmd/auth
```

Health check:
```bash
curl http://127.0.0.1:8083/internal/v1/health
```

## Migrações DB

Auth compartilha o **único Postgres** com o `viralefy_core` (modelo da Fase 8). Tabelas relevantes:

- `users` (auth lê email/password_hash/2fa fields; core lê profile fields)
- `admins` (idem)
- `admin_2fa`, `user_2fa`
- `refresh_tokens` (a criar — Fase 9b)
- `password_resets` (a criar — Fase 9b)
- `revoked_jtis` (a criar — Fase 9b, hot-set)
- `audit_log` (compartilhado, auth grava com `service=viralefy_auth`)

Migrations são donas do `viralefy_core` (single source of truth). Auth lê schema mas NÃO aplica DDL.

## Tests

```bash
go test -count=1 ./...
```

## Status checklist

- [x] Scaffold inicial: cmd/auth, config, health endpoint
- [ ] JWT mint/verify (RS256 + JWKS público)
- [ ] /login + /register + /refresh
- [ ] /password/reset (request + confirm)
- [ ] /twofa/* (TOTP RFC 6238 + AES-256-GCM)
- [ ] /token/verify + /token/revoke + hot-set
- [ ] systemd unit hardened + viralefy-update integration
- [ ] Dashboard Grafana
- [ ] Audit log estruturado
- [ ] Paridade E2E com core legacy
