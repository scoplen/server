# Scoplen server principles

Scoplen is a Plystra project. This record applies the shared adoption record in
[`../scoplen-docs/PROJECT_PRINCIPLES.md`](../scoplen-docs/PROJECT_PRINCIPLES.md) to the
self-hosted server, host agent, administration CLI, and web console.

## Current boundary

- The server owns durable service behavior, role supervision, operator configuration, and the
  web console. It does not own client source or shared wire contracts.
- The vendor does not receive deployment data. Operators control the server's data directory,
  keys, logs, backups, and retention.
- The repository is Exploration maturity until the roadmap evidence is complete. The baseline
  listener is useful for local development and reverse-proxy integration; it is not a complete
  production server.

## Open gaps

- ACME TLS-ALPN-01 issuance and renewal are integrated; live CA issuance and renewal have not been
  verified against an external authority.
- SQLite migrations, transactions, sync storage, an atomic retention primitive, and a durable
  leased job queue with worker lease cleanup exist. The API listener mounts the Personal K-4
  subset on SQLite or PostgreSQL with enrolled-device tokens, durable DPoP replay protection,
  current certificates, scopes, vault ownership, signed envelopes, and transaction-local write
  authorization. Configured rate and body limits apply across connections. Shared-vault mutations,
  account-key updates, and production notifications remain unmounted. Durable first-operator
  setup and maintained WebAuthn verification exist on both stores; their HTTP/console surfaces,
  operator sessions, invitation issuance, complete identity and policy workflows, membership-aware purge scheduling,
  certificate, gateway, audit, agent, CLI, and console behavior remain on the roadmap. The worker
  can use the PostgreSQL query backend; API and edge can start with PostgreSQL and check readiness.
- Deployment, backup/restore, upgrade, and release artifacts require their own validated gates.

## Review

Review this record with the project record before a new public surface or a maturity change.
