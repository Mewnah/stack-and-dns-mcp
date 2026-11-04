/**
 * Every schema change, in order. Each migration runs once, in its own
 * transaction, and the applied version is recorded in the meta table, so an
 * existing database upgrades in place. Never edit a released migration; add
 * a new one instead.
 *
 * The SQL lives here rather than next to the code that uses it so that the
 * database layer can apply every migration without importing (and forming a
 * cycle with) the feature modules.
 */

import type { Migration } from "./db.js";

export const MIGRATION_SCANS = `
  CREATE TABLE domains (
    domain TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    tech_scanned_at INTEGER,
    tech_ok_at INTEGER,
    email_scanned_at INTEGER,
    email_state TEXT
  );
  CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('tech', 'email')),
    source TEXT NOT NULL CHECK (source IN ('call', 'bulk', 'monitor', 'crawl')),
    scanned_at INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    score INTEGER,
    grade TEXT,
    summary TEXT NOT NULL
  );
  CREATE INDEX scans_by_domain ON scans (domain, kind, scanned_at DESC);
  CREATE INDEX scans_by_time ON scans (scanned_at);
  CREATE TABLE domain_tech (
    domain TEXT NOT NULL,
    tech_id TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    version TEXT,
    implied INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    missed INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    removed_at INTEGER,
    PRIMARY KEY (domain, tech_id)
  );
  CREATE INDEX domain_tech_by_tech ON domain_tech (tech_id, active, last_seen DESC);
  CREATE TABLE changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('tech', 'email')),
    change TEXT NOT NULL,
    subject TEXT,
    old_value TEXT,
    new_value TEXT,
    severity TEXT NOT NULL,
    at INTEGER NOT NULL
  );
  CREATE INDEX changes_by_domain ON changes (domain, at DESC);
  CREATE INDEX changes_by_time ON changes (at);
    `;

export const MIGRATION_BULK_JOBS = `
  CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    principal_plan TEXT NOT NULL,
    principal_label TEXT NOT NULL,
    principal_source TEXT NOT NULL,
    check_kind TEXT NOT NULL CHECK (check_kind IN ('email', 'tech', 'audit')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'cancelled')),
    submitted INTEGER NOT NULL,
    accepted INTEGER NOT NULL,
    credits_per_domain INTEGER NOT NULL,
    credits_charged INTEGER NOT NULL,
    day_units_charged INTEGER NOT NULL,
    credits_refunded INTEGER NOT NULL DEFAULT 0,
    day_units_refunded INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    finalized_at INTEGER
  );
  CREATE INDEX jobs_by_principal ON jobs (principal_id, created_at DESC);
  CREATE INDEX jobs_by_status ON jobs (status, created_at);
  CREATE TABLE job_items (
    job_id TEXT NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    idx INTEGER NOT NULL,
    input TEXT NOT NULL,
    domain TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'done', 'failed', 'skipped', 'cancelled')),
    result TEXT,
    error_code TEXT,
    error_message TEXT,
    finished_at INTEGER,
    PRIMARY KEY (job_id, idx)
  );
  CREATE INDEX job_items_by_status ON job_items (job_id, status, idx);
`;

export const MIGRATION_API_KEYS = `
  CREATE TABLE api_keys (
    key_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    prefix TEXT NOT NULL,
    plan TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL CHECK (source IN ('checkout', 'rotation')),
    checkout_session TEXT UNIQUE,
    stripe_customer TEXT,
    stripe_subscription TEXT,
    created_at INTEGER NOT NULL,
    deactivated_at INTEGER,
    deactivated_reason TEXT
  );
  CREATE INDEX api_keys_by_account ON api_keys (account_id);
  CREATE UNIQUE INDEX api_keys_one_active_per_account ON api_keys (account_id) WHERE active = 1;
  CREATE INDEX api_keys_by_subscription ON api_keys (stripe_subscription);
  CREATE TABLE stripe_events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    received_at INTEGER NOT NULL
  );
  CREATE TABLE subscription_state (
    subscription_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    plan TEXT,
    event_created INTEGER NOT NULL
  );
`;

export const MIGRATION_MONITORING = `
  CREATE TABLE watches (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    principal_plan TEXT NOT NULL,
    principal_label TEXT NOT NULL,
    principal_source TEXT NOT NULL,
    domain TEXT NOT NULL,
    checks TEXT NOT NULL,
    webhook_url TEXT,
    webhook_secret TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    paused_reason TEXT,
    last_checked_at INTEGER,
    alert_cursor INTEGER NOT NULL DEFAULT 0,
    UNIQUE (principal_id, domain)
  );
  CREATE INDEX watches_by_domain ON watches (domain);
  CREATE TABLE monitor_schedule (
    domain TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('email', 'tech')),
    next_at INTEGER NOT NULL,
    last_at INTEGER,
    last_error TEXT,
    PRIMARY KEY (domain, kind)
  );
  CREATE INDEX monitor_schedule_due ON monitor_schedule (next_at);
  CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id TEXT NOT NULL REFERENCES watches (id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    kind TEXT NOT NULL,
    change TEXT NOT NULL,
    subject TEXT,
    old_value TEXT,
    new_value TEXT,
    severity TEXT NOT NULL,
    at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    read_at INTEGER,
    delivery_status TEXT NOT NULL CHECK (delivery_status IN ('none', 'pending', 'delivered', 'failed')),
    delivery_attempts INTEGER NOT NULL DEFAULT 0,
    next_delivery_at INTEGER,
    last_delivery_error TEXT
  );
  CREATE INDEX alerts_by_principal ON alerts (principal_id, id);
  CREATE INDEX alerts_pending ON alerts (delivery_status, next_delivery_at);
  CREATE INDEX changes_by_domain_id ON changes (domain, id);
`;

export const MIGRATION_CRAWL = `
  CREATE TABLE crawl_targets (
    domain TEXT PRIMARY KEY,
    added_at INTEGER NOT NULL,
    next_at INTEGER NOT NULL,
    last_at INTEGER,
    last_status TEXT CHECK (last_status IN ('ok', 'blocked', 'unreachable', 'not_found', 'failed', 'robots_disallowed', 'robots_unreachable')),
    last_error TEXT,
    failures INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX crawl_targets_due ON crawl_targets (next_at);
`;

export const MIGRATION_SHARED_LEDGER = `
  CREATE TABLE credits (
    principal_id TEXT PRIMARY KEY,
    plan TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    balance INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE redeemed_payments (
    id TEXT PRIMARY KEY,
    at INTEGER NOT NULL
  );
  CREATE INDEX redeemed_payments_by_time ON redeemed_payments (at);
  ALTER TABLE job_items ADD COLUMN claimed_by TEXT;
  ALTER TABLE jobs ADD COLUMN charged_by TEXT;
`;

export const MIGRATION_CRAWL_TECH = `
  CREATE TABLE crawl_tech (
    domain TEXT NOT NULL,
    tech_id TEXT NOT NULL,
    version TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    missed INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    removed_at INTEGER,
    PRIMARY KEY (domain, tech_id)
  );
  CREATE INDEX crawl_tech_by_tech ON crawl_tech (tech_id, active, last_seen);
  ALTER TABLE crawl_targets ADD COLUMN tech_ok_at INTEGER;
  CREATE INDEX crawl_targets_last_at ON crawl_targets (last_at);
  CREATE INDEX crawl_targets_status ON crawl_targets (last_status);
`;

/**
 * Monitoring now needs an identified caller; watches anonymous principals
 * created before cannot be managed any more. The index lets deleting watches
 * cascade to their alerts without a scan of the whole alerts table per watch.
 */
export const MIGRATION_RETIRE_ANONYMOUS_WATCHES = `
  CREATE INDEX IF NOT EXISTS alerts_by_watch ON alerts (watch_id);
  DELETE FROM watches WHERE principal_source = 'anonymous';
`;

/**
 * x402 settlements in progress, shared by every process on the database: a
 * row is written before the facilitator is asked to settle, so a retry that
 * lands on another process (or after a restart) learns that money may have
 * moved instead of being sent a new payment demand.
 *
 * state: settling (request sent, no answer yet), unknown (the outcome could
 * not be confirmed: no answer, a 5xx, success without a transaction id, or a
 * refusal after an earlier unknown settle), settled (tx known, credits not
 * yet recorded). The row is deleted once the credits are recorded (here or
 * by a sibling), or when a first settle is refused; 'unknown' and 'settling'
 * rows are pruned after the marker retention (payments.ts
 * SETTLEMENT_MARKER_RETENTION_MS). Only this comment has changed since v8
 * was released; the SQL is as it shipped.
 */
export const MIGRATION_X402_SETTLEMENTS = `
  CREATE INDEX IF NOT EXISTS alerts_by_watch ON alerts (watch_id);
  CREATE TABLE x402_settlements (
    payment_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    label TEXT NOT NULL,
    credits INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('settling', 'unknown', 'settled')),
    tx TEXT,
    receipt TEXT,
    at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX x402_settlements_by_state ON x402_settlements (state, updated_at);
`;

/** pendingSettlementState looks up a session principal's unfinished settlements on every exhausted spending request. */
export const MIGRATION_X402_SETTLEMENTS_BY_PRINCIPAL = `
  CREATE INDEX IF NOT EXISTS x402_settlements_by_principal ON x402_settlements (principal_id);
`;

/**
 * Every monitor round first checks whether any anonymous watch is left to
 * retire (and then deletes a chunk of them). Without an index that check is
 * a scan of every watch, every round; this partial index holds only the
 * anonymous ones, normally none, so both statements become a lookup. Their
 * WHERE term must stay exactly principal_source = 'anonymous' for SQLite to
 * use it.
 */
export const MIGRATION_ANONYMOUS_WATCH_INDEX = `
  CREATE INDEX IF NOT EXISTS watches_anonymous ON watches (id) WHERE principal_source = 'anonymous';
`;

export const MIGRATIONS: Migration[] = [
  { version: 1, description: "stored scans, per-domain technology state and change log", sql: MIGRATION_SCANS },
  { version: 2, description: "bulk check jobs and self-serve API keys", sql: MIGRATION_BULK_JOBS + MIGRATION_API_KEYS },
  { version: 3, description: "domain monitoring: watches, check schedule and alerts", sql: MIGRATION_MONITORING },
  { version: 4, description: "crawl targets for reverse technology lookup", sql: MIGRATION_CRAWL },
  { version: 5, description: "shared credit ledger and redeemed payments; bulk item claim fencing", sql: MIGRATION_SHARED_LEDGER },
  { version: 6, description: "technology state observed by the crawler alone, for the reverse lookup", sql: MIGRATION_CRAWL_TECH },
  { version: 7, description: "retire watches owned by anonymous principals", sql: MIGRATION_RETIRE_ANONYMOUS_WATCHES },
  { version: 8, description: "shared x402 settlement markers; alerts indexed by watch", sql: MIGRATION_X402_SETTLEMENTS },
  { version: 9, description: "x402 settlement markers indexed by principal", sql: MIGRATION_X402_SETTLEMENTS_BY_PRINCIPAL },
  { version: 10, description: "anonymous watches indexed for the per-round retirement check", sql: MIGRATION_ANONYMOUS_WATCH_INDEX }
];
