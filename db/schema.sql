CREATE TABLE IF NOT EXISTS oauth_states (
  state_hash text PRIMARY KEY,
  expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_connections (
  account_uuid uuid PRIMARY KEY,
  access_token_ciphertext text NOT NULL,
  refresh_token_ciphertext text NOT NULL,
  expires_at timestamptz NOT NULL,
  scope text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS used_events (
  event_hash text PRIMARY KEY,
  expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS monitored_jobs (
  id uuid PRIMARY KEY,
  account_uuid uuid NOT NULL,
  job_uuid uuid NOT NULL,
  job_number text NOT NULL,
  job_address text NOT NULL,
  job_description text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'stopped')),
  baseline_complete boolean NOT NULL DEFAULT false,
  last_checked_at timestamptz,
  next_check_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  added_by_staff_uuid uuid NOT NULL,
  stopped_by_staff_uuid uuid,
  stopped_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (account_uuid, job_uuid)
);

CREATE INDEX IF NOT EXISTS monitored_jobs_due_idx
  ON monitored_jobs (next_check_at) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS consent_candidates (
  id uuid PRIMARY KEY,
  account_uuid uuid NOT NULL,
  monitored_job_id uuid NOT NULL REFERENCES monitored_jobs(id) ON DELETE CASCADE,
  identity_hash text NOT NULL,
  consent_number text NOT NULL DEFAULT '',
  event_date text NOT NULL DEFAULT '',
  action text NOT NULL DEFAULT '',
  description text NOT NULL DEFAULT '',
  source_url text NOT NULL DEFAULT '',
  was_issued boolean NOT NULL DEFAULT false,
  decision text NOT NULL CHECK (decision IN ('baseline', 'needs_review', 'ignored', 'confirmed')),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  decided_by_staff_uuid uuid,
  decided_at timestamptz,
  UNIQUE (monitored_job_id, identity_hash)
);

CREATE INDEX IF NOT EXISTS consent_candidates_job_idx ON consent_candidates (monitored_job_id);
