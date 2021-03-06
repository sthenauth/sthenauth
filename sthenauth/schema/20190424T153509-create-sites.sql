CREATE TABLE sites (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v1mc(),
  fqdn TEXT NOT NULL CHECK (LENGTH(fqdn) > 1),
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  policy JSONB NOT NULL,
  after_login_url TEXT NOT NULL DEFAULT '/',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  EXCLUDE (is_default WITH =) WHERE (is_default = TRUE)
);

CREATE UNIQUE INDEX ON sites (fqdn);

CREATE TRIGGER trigger_sites_updated_at
  BEFORE UPDATE ON sites
  FOR EACH ROW EXECUTE PROCEDURE trigger_updated_at();

/* ====================================================================== */
CREATE TABLE site_aliases (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v1mc(),
  site_id UUID NOT NULL REFERENCES sites ON DELETE CASCADE,
  fqdn TEXT NOT NULL CHECK (LENGTH(fqdn) > 1),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE UNIQUE INDEX ON site_aliases (fqdn);
CREATE INDEX ON site_aliases (site_id);

CREATE TRIGGER trigger_site_aliases_updated_at
  BEFORE UPDATE ON site_aliases
  FOR EACH ROW EXECUTE PROCEDURE trigger_updated_at();
