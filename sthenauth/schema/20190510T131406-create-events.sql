CREATE TABLE events (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v1mc(),
  actor_id   UUID NULL REFERENCES accounts ON DELETE SET NULL,
  remote     JSONB NOT NULL CHECK (remote ? 'address' AND LENGTH(remote->>'address') >= 1),
  detail     JSONB NOT NULL CHECK (detail ? 'tag' AND LENGTH(detail->>'tag') >= 1),
  created_at timestamp with time zone DEFAULT current_timestamp
);

CREATE INDEX ON events ((remote->>'address'));
CREATE INDEX ON events ((detail->>'tag'));

CREATE TRIGGER trigger_events_updated_at
  BEFORE UPDATE ON events
  FOR EACH ROW EXECUTE PROCEDURE trigger_updated_at();
