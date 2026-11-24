-- 0002: message requests, privacy settings, profile picture, last seen, encrypted media.
ALTER TABLE users ADD COLUMN avatar TEXT;
ALTER TABLE users ADD COLUMN allow_requests INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN profile_visibility TEXT NOT NULL DEFAULT 'everyone';
ALTER TABLE users ADD COLUMN last_seen_visibility TEXT NOT NULL DEFAULT 'contacts';
ALTER TABLE users ADD COLUMN read_receipts INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN last_seen INTEGER;
ALTER TABLE conversations ADD COLUMN accepted INTEGER NOT NULL DEFAULT 1;
ALTER TABLE conversations ADD COLUMN requested_by TEXT;
CREATE TABLE IF NOT EXISTS media (
  id              TEXT PRIMARY KEY,
  owner           TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  size            INTEGER NOT NULL,
  created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS media_owner ON media(owner);
CREATE INDEX IF NOT EXISTS media_created ON media(created_at);
