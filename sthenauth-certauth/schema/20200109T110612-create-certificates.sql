CREATE TYPE cert_use_t AS ENUM ('root', 'intermediate', 'localhost', 'client');

CREATE TABLE certificates (
  id          UUID PRIMARY KEY,
  parent_id   UUID REFERENCES certificates ON DELETE CASCADE,
  cert_use    cert_use_t NOT NULL,
  cert_pem    BYTEA NOT NULL,
  expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  CHECK (cert_use = 'root' OR parent_id IS NOT NULL)
);

CREATE INDEX ON certificates (expires_at);
CREATE INDEX ON certificates (parent_id, cert_use);
