-- Swift Akuru Chat — D1 (SQLite) schema.
-- The server is a mailbox: it stores end-to-end encrypted messages only until the recipient's
-- device acknowledges delivery, then clears the ciphertext. Phone numbers are stored only as
-- HMAC-SHA256(pepper, E.164). PINs and private keys never reach the server.

CREATE TABLE IF NOT EXISTS config (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  phone_hash    TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  discoverable  INTEGER NOT NULL DEFAULT 1,
  kem_pub       TEXT NOT NULL,              -- X25519 public key (base64, raw 32 bytes)
  key_version   INTEGER NOT NULL DEFAULT 1,
  key_updated_at INTEGER NOT NULL,
  created_at    INTEGER NOT NULL,
  deleted_at    INTEGER
);

CREATE TABLE IF NOT EXISTS otp_codes (
  phone_hash TEXT PRIMARY KEY,
  code_hash  TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  sent_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  device     TEXT,
  created_at INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS conversations (
  id           TEXT PRIMARY KEY,
  user_a       TEXT NOT NULL,               -- user_a < user_b (sorted), one conversation per pair
  user_b       TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  secret       INTEGER NOT NULL DEFAULT 0,  -- both users accepted a Secret Chat invitation
  secret_since INTEGER,
  UNIQUE (user_a, user_b)
);

CREATE TABLE IF NOT EXISTS conversation_members (
  conversation_id TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  hidden          INTEGER NOT NULL DEFAULT 0, -- "deleted" from this user's list
  PRIMARY KEY (conversation_id, user_id)
);
CREATE INDEX IF NOT EXISTS members_user ON conversation_members(user_id);

CREATE TABLE IF NOT EXISTS messages (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,
  id              TEXT NOT NULL UNIQUE,       -- client-generated UUID → no duplicates on retry
  conversation_id TEXT NOT NULL,
  sender_id       TEXT NOT NULL,              -- taken from the session, never from the client
  recipient_id    TEXT NOT NULL,
  enc             TEXT,                       -- HPKE encapsulated key (cleared after delivery)
  ciphertext      TEXT,                       -- HPKE ciphertext (cleared after delivery)
  key_version     INTEGER NOT NULL,           -- recipient key version the sender encrypted to
  sent_at         INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  delivered_at    INTEGER,
  read_at         INTEGER
);
CREATE INDEX IF NOT EXISTS messages_recipient ON messages(recipient_id, seq);
CREATE INDEX IF NOT EXISTS messages_conversation ON messages(conversation_id);

CREATE TABLE IF NOT EXISTS events (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    TEXT NOT NULL,
  type       TEXT NOT NULL,                   -- status | invite | invite_response | secret | key_changed | conversation
  payload    TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_user ON events(user_id, seq);

CREATE TABLE IF NOT EXISTS secret_invitations (
  id              TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL,
  from_user       TEXT NOT NULL,
  to_user         TEXT NOT NULL,
  status          TEXT NOT NULL,              -- pending | accepted | declined | expired | cancelled
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  responded_at    INTEGER
);
CREATE INDEX IF NOT EXISTS invitations_to ON secret_invitations(to_user, status);
CREATE INDEX IF NOT EXISTS invitations_conv ON secret_invitations(conversation_id, status);

CREATE TABLE IF NOT EXISTS blocks (
  blocker    TEXT NOT NULL,
  blocked    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (blocker, blocked)
);

CREATE TABLE IF NOT EXISTS reports (
  id              TEXT PRIMARY KEY,
  reporter        TEXT NOT NULL,
  reported        TEXT NOT NULL,
  conversation_id TEXT,
  reason          TEXT NOT NULL,
  created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
  k            TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL
);

-- Swift Akuru app accounts (Google sign-in), installs (anonymous app stats) and admin dashboard.
CREATE TABLE IF NOT EXISTS app_accounts (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,            -- 'google'
  sub TEXT NOT NULL,                 -- provider's stable user id
  email TEXT,
  name TEXT,
  picture TEXT,
  plan TEXT NOT NULL DEFAULT 'free',
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  UNIQUE (provider, sub)
);
CREATE TABLE IF NOT EXISTS app_sessions (
  token_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS app_sessions_account ON app_sessions(account_id);
CREATE TABLE IF NOT EXISTS app_installs (
  install_id TEXT PRIMARY KEY,
  account_id TEXT,
  app_version TEXT, build TEXT, ios TEXT, model TEXT, locale TEXT, source TEXT,
  keyboard_on INTEGER, full_access INTEGER,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  opens INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS app_installs_seen ON app_installs(last_seen);
CREATE TABLE IF NOT EXISTS app_daily (
  day TEXT NOT NULL, install_id TEXT NOT NULL,
  PRIMARY KEY (day, install_id)
);
CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  verifier TEXT NOT NULL,
  install_id TEXT,
  created_at INTEGER NOT NULL
);
