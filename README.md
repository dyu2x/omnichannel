# Mesina Farms Unified Support v1.02.1

Unified customer support inbox for Email (IMAP/SMTP), WhatsApp Cloud API and website Live Chat. Built with Node.js 22, Express, PostgreSQL 16, Redis and ZITADEL OIDC.

## v1.02.1 — Email integration

This release builds on the v1.01.6 fresh-install baseline. It retains the existing ZITADEL login, agent profile/avatar synchronization, local role permissions, unified inbox, contacts, teams, assignment, WhatsApp and Live Chat functionality.

### Email capabilities

- Configure multiple inbound IMAP and outbound SMTP mailboxes from Admin Settings → Email Settings.
- Separate IMAP and SMTP host, port, username, password and TLS settings.
- Encrypted-at-rest mailbox credentials using the existing `ENCRYPTION_KEY`.
- Test IMAP and SMTP connectivity before relying on an account.
- Automatic inbound mailbox polling every 60 seconds, plus a per-account **Sync now** action.
- Per-account last synchronization timestamp and last error status.
- IMAP UID + UIDVALIDITY receipt tracking and database advisory locks to prevent duplicate ingestion across polling cycles and application instances.
- Email contact matching and automatic contact creation for unknown senders.
- Email threading using `Message-ID`, `In-Reply-To` and `References`, including multi-reply chains.
- Replies use the same mailbox that received the conversation whenever possible, and include `In-Reply-To` / `References` headers to keep the customer's email thread together.
- SMTP TLS behaviour respects the configured security option and port.
- Inbound attachments are stored in PostgreSQL up to 15 MB each. Outbound email replies support up to 10 attachments, 10 MB per file and 20 MB total.
- Attachments are only downloadable by agents who can access the parent conversation; downloads use attachment disposition and `nosniff`.
- Team email routing is based on actual To/Cc recipient addresses, not simply the mailbox being polled.
- Email account connection and synchronization failures are written to email sync logs and shown in Email Settings.

### Email provider settings examples

Use the values supplied by your email hosting provider. These are examples only.

| Provider type | IMAP | SMTP |
|---|---|---|
| Typical SSL/TLS | Port 993, SSL/TLS enabled | Port 465, TLS enabled |
| Typical STARTTLS | Port 143, STARTTLS option | Port 587, TLS required / STARTTLS |

For SMTP port 587, choose **Require TLS**. For port 465, choose **Require TLS** (implicit TLS is used automatically). Avoid unencrypted connections unless your mail provider explicitly requires them.

### Purelymail recommended settings

| Field | Value |
|---|---|
| IMAP host | `imap.purelymail.com` |
| IMAP port | `993` |
| IMAP security | SSL/TLS enabled |
| IMAP username | Full mailbox email address |
| IMAP folder | `INBOX` |
| SMTP host | `smtp.purelymail.com` |
| SMTP port | `465` |
| SMTP security | TLS enabled (implicit TLS on 465) |
| SMTP username | Full mailbox email address |
| Password | Mailbox password, or an app password when 2FA is enabled |

SMTP port `587` with STARTTLS is an alternative if port 465 is blocked. SMTP authentication is required. Do not use a `user+tag@domain` subaddress as the login username.

### v1.02.1 email ingestion correction

The v1.02.0 IMAP ingestion path passed JavaScript arrays directly to PostgreSQL `jsonb` columns. The PostgreSQL driver encoded those values as PostgreSQL arrays, causing `invalid input syntax for type json`. v1.02.1 explicitly serializes `to_addresses`, `cc_addresses`, and outbound email metadata as JSON before insertion. Existing mailbox UIDs that failed before transaction commit remain eligible for a retry; run **Sync now** after upgrading.

## Fresh installation

1. Extract this bundle into your application directory.
2. Copy `.env.example` to `.env`.
3. Set strong unique values for `SESSION_SECRET`, `ENCRYPTION_KEY` (base64 encoding of exactly 32 random bytes), and `POSTGRES_PASSWORD`.
4. Keep your current ZITADEL settings if continuing the existing environment: issuer `https://auth.mesina.farm`, current web client ID and secret, callback URL `https://support.mesina.farm/callback`, and logout URL `https://support.mesina.farm/`. No new ZITADEL configuration is required.
5. Set `BOOTSTRAP_ADMIN_EMAIL` to the exact email address of the intended Super Admin.
6. Start with `docker compose up -d --build`.
7. Open `https://support.mesina.farm` through the existing Cloudflare Tunnel. The app listens on port 3000 inside Docker. PostgreSQL is bound to `127.0.0.1:5432`; Redis is internal to the Compose network.

### Important database note

This is a **fresh-install bundle**. `db/init.sql` is the single consolidated initial PostgreSQL schema. There is no `migrations/` directory and no separate migration files in this ZIP. PostgreSQL runs `db/init.sql` only when initializing a new empty data directory.

Do not delete or replace an existing production PostgreSQL volume to install this package. Back up first and use a separately planned in-place upgrade procedure if upgrading an existing installation. The application retains idempotent startup compatibility checks for known prior schema fields; these are in `src/server.js`, not separate migration files.

## ZITADEL and local roles

ZITADEL remains the identity provider. Agent display name, avatar and available profile claims are refreshed from ZITADEL when the user signs in. Application roles and `is_active` status remain local in PostgreSQL. Super Admin can assign all application roles. Admin can assign Manager and Agent only; only Super Admin can modify Admin/Super Admin accounts.

## Deployment

For a clean fresh install:

```bash
cp .env.example .env
# Edit .env and set strong secrets and ZITADEL credentials
docker compose up -d --build
docker compose ps
docker compose logs -f app
```

For a rebuild after replacing application files, preserve `.env` and the PostgreSQL volume:

```bash
docker compose build --no-cache app
docker compose up -d --force-recreate app
docker compose logs --tail=150 app
```

Never use `docker compose down -v` unless intentionally deleting all persistent data.

## Useful commands

```bash
docker compose ps
docker compose logs -f app
docker compose logs -f postgres
curl -fsS http://127.0.0.1:3000/health
```

## Package contents

- `db/init.sql` — consolidated initial PostgreSQL schema
- `src/server.js` — Express application, ZITADEL OIDC, APIs and IMAP/SMTP integrations
- `public/` — WebUI, styles and embeddable Live Chat widget
- `.env.example` — configuration template
- `Dockerfile` and `docker-compose.yml` — container build and deployment

No migration files are included in this package.
