/* ---------------------------------------------------------------------------- */
CREATE TABLE accounts (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v1mc(),
  site_id    UUID NOT NULL REFERENCES sites ON DELETE CASCADE,
  username   TEXT CHECK(username IS NULL OR LENGTH(username) > 1),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE UNIQUE INDEX ON accounts (username);

CREATE TRIGGER trigger_accounts_updated_at
  BEFORE UPDATE ON accounts
  FOR EACH ROW EXECUTE PROCEDURE trigger_updated_at();

/* ---------------------------------------------------------------------------- */
CREATE TABLE accounts_local (
  account_id UUID NOT NULL REFERENCES accounts ON DELETE CASCADE,
  password   JSONB NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE UNIQUE INDEX ON accounts_local (account_id);

CREATE TRIGGER trigger_accounts_local_updated_at
  BEFORE UPDATE ON accounts_local
  FOR EACH ROW EXECUTE PROCEDURE trigger_updated_at();
