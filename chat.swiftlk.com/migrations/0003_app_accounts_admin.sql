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
