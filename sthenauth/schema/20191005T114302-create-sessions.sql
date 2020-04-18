CREATE TABLE sessions (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v1mc(),
  site_id     UUID NOT NULL REFERENCES sites ON DELETE CASCADE,
  account_id  UUID NOT NULL REFERENCES accounts ON DELETE CASCADE,
  remote      JSONB NOT NULL,
  session_key BYTEA NOT NULL,
  expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
  inactive_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE UNIQUE INDEX ON sessions (site_id, session_key);
CREATE INDEX ON sessions (site_id, account_id);

CREATE TRIGGER trigger_sessions_updated_at
  BEFORE UPDATE ON sessions
  FOR EACH ROW EXECUTE PROCEDURE trigger_updated_at();
