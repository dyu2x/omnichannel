# Mesina Farms Unified Support v1.01.6

Unified inbox for Email, WhatsApp and website Live Chat, using PostgreSQL, Redis and ZITADEL OIDC.

## Fresh installation

1. Copy `.env.example` to `.env`.
2. Set strong unique values for `SESSION_SECRET`, `ENCRYPTION_KEY` (base64 encoding of exactly 32 random bytes), and `POSTGRES_PASSWORD`.
3. Keep your existing ZITADEL values unchanged: issuer `https://auth.mesina.farm`, your current web client ID and secret, callback URL `https://support.mesina.farm/callback`, and logout URL `https://support.mesina.farm/`. The callback URL must also remain registered in the same ZITADEL application.
4. Ensure the ZITADEL application continues to use the same client type, redirect URI, post-logout redirect URI, and scopes as your current deployment. This release does not require changes to ZITADEL configuration.
5. Start the stack: `docker compose up -d --build`.
6. Open `https://support.mesina.farm` through your existing Cloudflare Tunnel. The app listens on port 3000 inside Docker. PostgreSQL is bound to `127.0.0.1:5432` for local pgAdmin access; Redis is internal to the Compose network.
7. Set `BOOTSTRAP_ADMIN_EMAIL` to the exact email address of the administrator who signs in through ZITADEL. On every sign-in, that matching account is guaranteed to have the local Super Admin role, including accounts that already existed before this release. Existing accounts with no local role are automatically assigned Agent. Other users' ZITADEL profile data is synchronized, but their application roles remain local.

## Important fresh-install warning

This bundle is intentionally clean and contains no migration scripts. `db/init.sql` is the single initial schema and runs only when PostgreSQL initializes a new, empty data directory. Use a new/empty Docker volume for a fresh install. **Do not delete or replace an existing production database volume unless you have a verified backup and explicitly intend to start with an empty database.** This package is not an in-place upgrade procedure for v1.01.1.

## ZITADEL and local roles

ZITADEL remains the identity provider. Agent display name, avatar and available profile claims are refreshed from ZITADEL when the user signs in. Application roles and `is_active` status are stored locally in PostgreSQL. Super Admin can assign all application roles. Admin can assign Manager and Agent only; only Super Admin can modify Admin/Super Admin accounts.

## WebUI v1.01.6

- Sidebar can be collapsed to icon-only mode; the choice persists in the browser.
- WebUI Settings controls sidebar icon foreground color, background color and shape.
- Sidebar icons have a small randomized movement on pointer hover.
- Signed-in agent details, application version and logout control appear in the upper-right header.
- Registered Agents supports local role assignment and active/inactive status.
- Teams & Assignment supports team name/member updates and team deletion (role restricted).
- Email Settings supports removing connected inboxes and shows a checkmark for each connected account.

## Useful commands

```bash
docker compose ps
docker compose logs -f app
docker compose logs -f postgres
curl -fsS http://127.0.0.1:3000/health
```

## Files

- `db/init.sql` — complete initial PostgreSQL schema
- `src/server.js` — Express application, ZITADEL OIDC, API and integrations
- `public/` — WebUI and embeddable Live Chat widget
- `.env.example` — configuration template


## v1.01.5 fresh-install notes
- `db/init.sql` is the consolidated initial schema; it contains no `ALTER TABLE` migration statements.
- Use a new PostgreSQL volume for a clean installation. This bundle does not migrate or overwrite an existing database.
- Preserve the current ZITADEL issuer, client ID/secret, callback, logout URL, and registered redirect URIs in `.env`; no ZITADEL application changes are required.
- Session cookies use a one-hour rolling expiration, so activity renews the session and inactivity expires it.
- Super Admin database export creates a SQL export and arms operational-data truncation for three minutes. Truncation preserves application configuration, registered users, roles, permissions, and integration settings.


## v1.01.5 update notes

- Admin Settings sub-pages include a return button to the Admin Settings selection.
- Super Admin can import an application-generated SQL export. Import is transactional and restores all application tables (including users, roles, settings and encrypted integration credentials) into the target database, replacing the existing application data; back up first and retain the same ENCRYPTION_KEY for encrypted settings.
- The operational-data truncate control remains disabled/grey until a successful SQL export arms it, and displays the three-minute authorization countdown.
- Customer directory deletion is exposed only to Super Admin.
- Navigation icon colors, backgrounds, and shapes can be configured independently for each navigation section.
- Activity history records the section, request before/after snapshots where available, and the client public IPv4 when the reverse proxy provides an IPv4 address.
- Admin Settings includes role restrictions for changing permission grants by role. Super Admin's permissions are fixed.
- Email Routing lets Admin and Super Admin assign enabled addresses configured in Email Settings to teams. Incoming email received by a routed inbox is assigned to its selected team.

### Upgrade / migration

The application runs idempotent compatibility migrations at startup for the new `teams.routing_email` and activity/audit fields. Keep your existing `.env` and persistent PostgreSQL volume when upgrading. For a fresh install, use the included `docker-compose.yml` and `.env.example`.


## v1.01.6 email inbox fixes

- Email team routing now matches each message's actual To/Cc recipients against the configured team routing address. It no longer assigns every message fetched from a mailbox to that mailbox's team.
- The All Conversations filters continue to combine status, channel, and assigned team as separate filters; selecting Email + Sales now returns email conversations actually assigned to Sales.
- Email ingestion records each IMAP delivery by account, folder, UIDVALIDITY, and UID, and uses an advisory lock plus the existing message uniqueness constraint to prevent repeat polling and concurrent duplicate inserts.
- IMAP UIDVALIDITY changes reset the mailbox cursor safely so a mailbox UID reset does not cause stale cursor behaviour.
- Email replies are matched using any available In-Reply-To / References message IDs, including multi-reply chains, so replies are added to the existing conversation rather than creating a new conversation for each reply.
- The new email ingestion receipt table is included in SQL export/import and operational-data truncation. Existing PostgreSQL volumes are updated by an idempotent startup migration; keep your existing `.env` and database volume when upgrading.

### Upgrade from v1.01.5

Back up PostgreSQL first, replace the application files with this v1.01.6 bundle, then rebuild and restart the app service. Do not remove the `postgres_data` volume and do not run a fresh-install database reset. The startup migration adds the UIDVALIDITY cursor and receipt table automatically. Existing incorrectly assigned conversations are not automatically reassigned, because the system cannot distinguish old automatic assignments from manual team assignments; review and reassign those existing records in the inbox if needed.


## v1.02 — Email integration

This release builds on the existing IMAP ingestion and SMTP reply support.

- Configure IMAP and SMTP independently, including TLS, mailbox folder, sender display name and Reply-To.
- Edit an existing mailbox without re-entering stored passwords; credentials remain encrypted with AES-256-GCM.
- Test IMAP authentication and mailbox access plus SMTP transport verification.
- Manually request mailbox synchronization and review the latest sync logs/errors.
- Incoming email is deduplicated using mailbox UIDVALIDITY/UID receipts and Internet Message-ID.
- Email replies prefer the mailbox that received the conversation and include In-Reply-To / References headers for threading.
- Email account schema upgrades are additive and run at application startup.
- Existing database volumes and `.env` are retained during upgrades.

### Email provider settings

Typical configurations:
- IMAP: port 993 with TLS enabled.
- SMTP submission: port 587 with STARTTLS required.
- SMTP implicit TLS: port 465 (TLS is enabled automatically based on the port).

Use provider-specific app passwords where applicable. Never expose mailbox passwords in logs or screenshots.
