CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS roles (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text UNIQUE NOT NULL, description text,
 is_system boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS permissions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), code text UNIQUE NOT NULL, description text NOT NULL);
CREATE TABLE IF NOT EXISTS role_permissions (role_id uuid REFERENCES roles(id) ON DELETE CASCADE, permission_id uuid REFERENCES permissions(id) ON DELETE CASCADE, PRIMARY KEY(role_id,permission_id));
CREATE TABLE IF NOT EXISTS users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), zitadel_sub text UNIQUE NOT NULL, email text, display_name text,
 avatar_url text, is_active boolean NOT NULL DEFAULT true, given_name text, family_name text, nickname text, preferred_username text, phone_number text, phone_number_verified boolean, email_verified boolean, profile_url text, website text, locale text, zoneinfo text, address jsonb, raw_profile jsonb NOT NULL DEFAULT '{}', last_seen_at timestamptz, first_login_at timestamptz, last_login_at timestamptz, is_online boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS user_roles (user_id uuid REFERENCES users(id) ON DELETE CASCADE, role_id uuid REFERENCES roles(id) ON DELETE RESTRICT, assigned_by uuid REFERENCES users(id), assigned_at timestamptz DEFAULT now(), PRIMARY KEY(user_id,role_id));
CREATE TABLE IF NOT EXISTS teams (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text UNIQUE NOT NULL, routing_email text, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS team_members (team_id uuid REFERENCES teams(id) ON DELETE CASCADE, user_id uuid REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(team_id,user_id));
CREATE TABLE IF NOT EXISTS contacts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text, email text, phone text, external_ids jsonb NOT NULL DEFAULT '{}', metadata jsonb NOT NULL DEFAULT '{}', first_name text, last_name text, company text, notes text, source text, custom_fields jsonb NOT NULL DEFAULT '{}', created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS contacts_email_lower_uq ON contacts(lower(email)) WHERE email IS NOT NULL AND email <> '';
CREATE TABLE IF NOT EXISTS conversations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), contact_id uuid REFERENCES contacts(id), channel text NOT NULL CHECK(channel IN ('email','whatsapp','livechat')),
 subject text, status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','pending','resolved','closed')),
 priority text NOT NULL DEFAULT 'normal', assigned_user_id uuid REFERENCES users(id), assigned_team_id uuid REFERENCES teams(id),
 external_thread_id text, snoozed_until timestamptz, inbox_name text, last_message_at timestamptz, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now(), closed_at timestamptz
);
CREATE INDEX IF NOT EXISTS conversations_queue_idx ON conversations(status,assigned_user_id,updated_at DESC);
CREATE INDEX IF NOT EXISTS conversations_team_queue_idx ON conversations(assigned_team_id,status,updated_at DESC);
CREATE INDEX IF NOT EXISTS contacts_name_search_idx ON contacts USING gin (to_tsvector('simple', coalesce(name,'') || ' ' || coalesce(email,'') || ' ' || coalesce(phone,'')));
CREATE TABLE IF NOT EXISTS messages (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
 channel text NOT NULL CHECK(channel IN ('email','whatsapp','livechat')), direction text NOT NULL CHECK(direction IN ('inbound','outbound','internal')),
 sender_name text, sender_address text, body_text text, body_html text, provider_message_id text, provider_status text,
 raw_payload jsonb NOT NULL DEFAULT '{}', created_by uuid REFERENCES users(id), created_at timestamptz DEFAULT now(),
 UNIQUE(channel,provider_message_id)
);
CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id,created_at);
CREATE TABLE IF NOT EXISTS message_attachments (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), message_id uuid REFERENCES messages(id) ON DELETE CASCADE, file_name text, mime_type text, storage_path text, size_bytes bigint, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS conversation_assignments (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), conversation_id uuid REFERENCES conversations(id) ON DELETE CASCADE, from_user_id uuid REFERENCES users(id), to_user_id uuid REFERENCES users(id), assigned_by uuid REFERENCES users(id), action text NOT NULL, note text, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS conversation_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), conversation_id uuid REFERENCES conversations(id) ON DELETE CASCADE, actor_user_id uuid REFERENCES users(id), event_type text NOT NULL, old_value jsonb, new_value jsonb, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS conversation_notes (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), conversation_id uuid REFERENCES conversations(id) ON DELETE CASCADE, author_user_id uuid REFERENCES users(id), body text NOT NULL, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS tags (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text UNIQUE NOT NULL, color text DEFAULT '#64748b');
CREATE TABLE IF NOT EXISTS conversation_tags (conversation_id uuid REFERENCES conversations(id) ON DELETE CASCADE, tag_id uuid REFERENCES tags(id) ON DELETE CASCADE, PRIMARY KEY(conversation_id,tag_id));
CREATE TABLE IF NOT EXISTS email_accounts (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, email_address text NOT NULL, imap_host text NOT NULL, imap_port int NOT NULL DEFAULT 993, imap_tls boolean DEFAULT true, imap_user text NOT NULL, imap_secret_enc text NOT NULL, smtp_host text NOT NULL, smtp_port int NOT NULL DEFAULT 587, smtp_tls boolean DEFAULT true, smtp_user text NOT NULL, smtp_secret_enc text NOT NULL, folder_name text DEFAULT 'INBOX', enabled boolean DEFAULT true, last_uid bigint DEFAULT 0, last_uidvalidity text, from_name text, reply_to text, sync_interval_seconds int NOT NULL DEFAULT 60, last_sync_at timestamptz, last_sync_error text, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS email_messages (message_id uuid PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE, account_id uuid REFERENCES email_accounts(id), internet_message_id text, in_reply_to text, references_header text, from_address text, to_addresses jsonb DEFAULT '[]', cc_addresses jsonb DEFAULT '[]', subject text);
CREATE TABLE IF NOT EXISTS email_ingest_receipts (account_id uuid NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE, folder_name text NOT NULL, uidvalidity text NOT NULL, uid bigint NOT NULL, message_id uuid REFERENCES messages(id) ON DELETE SET NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(account_id,folder_name,uidvalidity,uid));
CREATE INDEX IF NOT EXISTS email_ingest_receipts_message_idx ON email_ingest_receipts(message_id);
CREATE TABLE IF NOT EXISTS email_sync_logs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), account_id uuid REFERENCES email_accounts(id), level text, message text, details jsonb DEFAULT '{}', created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS whatsapp_accounts (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, phone_number_id text NOT NULL, business_account_id text, app_id text, app_secret_enc text, access_token_enc text NOT NULL, verify_token_enc text NOT NULL, graph_api_version text DEFAULT 'v23.0', enabled boolean DEFAULT true, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS whatsapp_messages (message_id uuid PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE, account_id uuid REFERENCES whatsapp_accounts(id), wa_message_id text UNIQUE, wa_from text, message_type text, context_message_id text, status text);
CREATE TABLE IF NOT EXISTS whatsapp_templates (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), account_id uuid REFERENCES whatsapp_accounts(id), template_name text NOT NULL, language text, status text, components jsonb DEFAULT '[]');
CREATE TABLE IF NOT EXISTS whatsapp_webhook_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), account_id uuid REFERENCES whatsapp_accounts(id), provider_event_id text, payload jsonb NOT NULL, processed_at timestamptz, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS whatsapp_message_statuses (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), wa_message_id text NOT NULL, status text NOT NULL, event_timestamp timestamptz, recipient_id text, payload jsonb DEFAULT '{}', created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS livechat_websites (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, domain text NOT NULL, public_key text UNIQUE NOT NULL DEFAULT encode(gen_random_bytes(18),'hex'), enabled boolean DEFAULT true, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS livechat_inboxes (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), website_id uuid REFERENCES livechat_websites(id) ON DELETE CASCADE, name text NOT NULL, welcome_message text, offline_message text, primary_color text DEFAULT '#2563eb', logo_url text, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS livechat_visitors (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), website_id uuid REFERENCES livechat_websites(id), visitor_token text UNIQUE NOT NULL, name text, email text, page_url text, metadata jsonb DEFAULT '{}', created_at timestamptz DEFAULT now(), last_seen_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS livechat_sessions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), visitor_id uuid REFERENCES livechat_visitors(id), conversation_id uuid REFERENCES conversations(id), started_at timestamptz DEFAULT now(), ended_at timestamptz);
CREATE TABLE IF NOT EXISTS livechat_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), visitor_id uuid REFERENCES livechat_visitors(id), event_type text, payload jsonb DEFAULT '{}', created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS agent_activity_logs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid REFERENCES users(id), action text NOT NULL, entity_type text, entity_id uuid, details jsonb DEFAULT '{}', ip_address inet, public_ipv4 text, user_agent text, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS audit_logs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), actor_user_id uuid REFERENCES users(id), action text NOT NULL, entity_type text, entity_id text, before_data jsonb, after_data jsonb, ip_address inet, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS system_settings (key text PRIMARY KEY, value jsonb NOT NULL DEFAULT '{}', updated_by uuid REFERENCES users(id), updated_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS branding_settings (id int PRIMARY KEY DEFAULT 1 CHECK(id=1), company_name text NOT NULL DEFAULT 'Mesina Farms', logo_path text, favicon_path text, primary_color text DEFAULT '#2563eb', secondary_color text DEFAULT '#0f172a', footer_text text DEFAULT '', updated_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS webhook_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), provider text NOT NULL, event_key text, payload jsonb NOT NULL, processed_at timestamptz, error text, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS integration_logs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), channel text NOT NULL, account_id uuid, level text, message text, details jsonb DEFAULT '{}', created_at timestamptz DEFAULT now());
INSERT INTO roles(name,description,is_system) VALUES ('Super Admin','Full system access',true),('Admin','Manage users, settings, integrations and inboxes',true),('Manager','Manage teams and assign conversations',true),('Agent','Handle conversations',true) ON CONFLICT(name) DO NOTHING;
INSERT INTO permissions(code,description) VALUES
('inbox.view','View permitted conversations'),('conversation.claim','Claim unassigned conversations'),('conversation.reply','Reply to conversations'),('conversation.assign','Assign and reassign conversations'),('conversation.manage_all','View all team conversations'),('conversation.delete','Delete conversations'),('users.manage','Manage users'),('roles.manage','Manage roles and permissions'),('settings.manage','Manage application settings'),('integrations.manage','Manage channel integrations'),('branding.manage','Manage company branding'),('audit.view','View audit and agent activity'),('contacts.view','View contacts and contact history'),('contacts.manage','Create and edit contacts'),('conversation.note','Add internal conversation notes'),('teams.manage','Manage teams and team membership'),('teams.delete','Delete teams'),('conversation.status','Change conversation status') ON CONFLICT(code) DO NOTHING;
INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name='Super Admin' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('inbox.view','conversation.claim','conversation.reply','conversation.status','contacts.view','conversation.note') WHERE r.name='Agent' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('inbox.view','conversation.claim','conversation.reply','conversation.assign','conversation.manage_all','conversation.status','contacts.view','contacts.manage','conversation.note','teams.manage','audit.view') WHERE r.name='Manager' ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('inbox.view','conversation.claim','conversation.reply','conversation.assign','conversation.manage_all','conversation.status','contacts.view','contacts.manage','conversation.note','teams.manage','users.manage','integrations.manage','branding.manage','audit.view') WHERE r.name='Admin' ON CONFLICT DO NOTHING;
INSERT INTO branding_settings(id) VALUES(1) ON CONFLICT(id) DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id) SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code='teams.delete' WHERE r.name IN ('Super Admin','Admin') ON CONFLICT DO NOTHING;

