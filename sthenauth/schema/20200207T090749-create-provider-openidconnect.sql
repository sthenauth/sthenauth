/* ---------------------------------------------------------------------------- */
CREATE TABLE providers_openidconnect (
  id                   UUID PRIMARY KEY DEFAULT uuid_generate_v1mc(),
  site_id              UUID NOT NULL REFERENCES sites ON DELETE CASCADE,
  enabled              BOOL NOT NULL,
  provider_name        TEXT NOT NULL,
  logo_url             TEXT NULL,
  client_id            TEXT NOT NULL,
  client_secret        JSONB NOT NULL,
  discovery_url        TEXT NOT NULL,
  discovery_doc        JSONB NOT NULL,
  discovery_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  jwk_set              JSONB NOT NULL,
  jwk_set_expires_at   TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  updated_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE UNIQUE INDEX ON providers_openidconnect (id, site_id);
CREATE INDEX ON providers_openidconnect (enabled);

CREATE TRIGGER trigger_providers_openidconnect_updated_at
  BEFORE UPDATE ON providers_openidconnect
  FOR EACH ROW EXECUTE PROCEDURE trigger_updated_at();

/* ---------------------------------------------------------------------------- */
CREATE TABLE accounts_openidconnect (
  account_id        UUID NOT NULL REFERENCES accounts ON DELETE CASCADE,
  site_id           UUID NOT NULL REFERENCES sites ON DELETE CASCADE,
  provider_id       UUID NOT NULL REFERENCES providers_openidconnect ON DELETE CASCADE,
  foreign_id        varchar(255) NOT NULL,
  access_token      JSONB NOT NULL,
  refresh_token     JSONB NULL,
  access_scope      JSONB NOT NULL,
  token_type        TEXT NOT NULL,
  id_token          JSONB NOT NULL,
  access_expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (current_timestamp + '1 hour'),
  id_expires_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (current_timestamp + '1 hour'),
  created_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  updated_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE INDEX ON accounts_openidconnect (account_id, site_id);
CREATE UNIQUE INDEX ON accounts_openidconnect (provider_id, foreign_id);

CREATE TRIGGER trigger_accounts_openidconnect_updated_at
  BEFORE UPDATE ON accounts_openidconnect
  FOR EACH ROW EXECUTE PROCEDURE trigger_updated_at();

/* ---------------------------------------------------------------------------- */
CREATE TABLE openidconnect_cookies (
  hashed_cookie BYTEA PRIMARY KEY,
  site_id       UUID NOT NULL REFERENCES sites ON DELETE CASCADE,
  provider_id   UUID NOT NULL REFERENCES providers_openidconnect ON DELETE CASCADE,
  expires_at    TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE INDEX ON openidconnect_cookies (hashed_cookie, created_at, site_id);
