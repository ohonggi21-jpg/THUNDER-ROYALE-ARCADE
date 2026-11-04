CREATE TABLE IF NOT EXISTS players (
  id TEXT PRIMARY KEY,
  data_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_players_updated_at ON players(updated_at DESC);

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_uid TEXT NOT NULL,
  action TEXT NOT NULL,
  player_id TEXT,
  note TEXT NOT NULL DEFAULT '',
  before_json TEXT,
  after_json TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_created_at ON admin_audit(created_at DESC);
