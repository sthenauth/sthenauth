CREATE TABLE accounts (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v1mc(),
  site_id    UUID NOT NULL REFERENCES sites ON DELETE CASCADE,
  username   TEXT CHECK(username IS NULL OR LENGTH(username) > 1),
  password   JSONB NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE INDEX ON accounts (site_id);
CREATE UNIQUE INDEX ON accounts (site_id, username);

CREATE TRIGGER trigger_accounts_updated_at
  BEFORE UPDATE ON accounts
  FOR EACH ROW EXECUTE PROCEDURE trigger_updated_at();
