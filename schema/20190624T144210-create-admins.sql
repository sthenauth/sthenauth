CREATE TABLE admins (
  account_id UUID NOT NULL REFERENCES accounts ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT current_timestamp
);

CREATE UNIQUE INDEX ON admins (account_id);
