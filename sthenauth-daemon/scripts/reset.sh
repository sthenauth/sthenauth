#!/bin/sh

set -e
set -u

email="admin@example.com"
password="ooYuBezoo2EiwaeciCha"

export STHENAUTH_SECRETS_DIR="${STHENAUTH_SECRETS_DIR:-tmp}"

dropdb sthenauth && \
  createdb sthenauth && \
  rm -rf "$STHENAUTH_SECRETS_DIR"

echo 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";' | \
  psql sthenauth

cabal run sthenauth -- \
  --email "${email}" \
  --password "${password}"  \
  init

cabal run sthenauth -- \
  --email "${email}" \
  --password "${password}"  \
  info

cabal run sthenauth -- \
  --email "${email}" \
  --password "${password}"  \
  policy mode --self-service

cabal run sthenauth -- \
  server --port=3001
