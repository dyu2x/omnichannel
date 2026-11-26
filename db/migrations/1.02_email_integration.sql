-- Mesina Farms Unified Support v1.02 email integration upgrade
-- Safe to run repeatedly; preserves existing mailbox credentials and messages.
BEGIN;
ALTER TABLE email_accounts ADD COLUMN IF NOT EXISTS from_name text;
ALTER TABLE email_accounts ADD COLUMN IF NOT EXISTS reply_to text;
ALTER TABLE email_accounts ADD COLUMN IF NOT EXISTS sync_interval_seconds int NOT NULL DEFAULT 60;
ALTER TABLE email_accounts ADD COLUMN IF NOT EXISTS last_sync_at timestamptz;
ALTER TABLE email_accounts ADD COLUMN IF NOT EXISTS last_sync_error text;
ALTER TABLE email_messages ADD COLUMN IF NOT EXISTS internet_message_id text;
ALTER TABLE email_messages ADD COLUMN IF NOT EXISTS in_reply_to text;
ALTER TABLE email_messages ADD COLUMN IF NOT EXISTS references_header text;
CREATE INDEX IF NOT EXISTS email_messages_internet_id_idx ON email_messages(internet_message_id);
CREATE INDEX IF NOT EXISTS email_messages_thread_idx ON email_messages(account_id,in_reply_to);
COMMIT;
