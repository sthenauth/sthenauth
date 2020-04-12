CREATE TABLE emails (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v1mc(),
  account_id  UUID NOT NULL REFERENCES accounts ON DELETE CASCADE,
  email       JSONB NOT NULL CHECK (email ? 'hashed' AND LENGTH(email->>'hashed') >= 1),
  verified_at TIMESTAMP WITH TIME ZONE     NULL,
  created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE UNIQUE INDEX ON emails (((email->>'hashed')::BYTEA));
CREATE INDEX ON emails (account_id);

CREATE TRIGGER trigger_emails_updated_at
  BEFORE UPDATE ON emails
  FOR EACH ROW EXECUTE PROCEDURE trigger_updated_at();
