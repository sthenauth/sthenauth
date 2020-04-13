#!/bin/sh

set -e
set -u

email="admin@example.com"
password="ooYuBezoo2EiwaeciCha"

export BASEDIR="$(pwd)/tmp"
export STHENAUTH_CONFIG="$BASEDIR/config.yml"
export STHENAUTH_SECRETS_DIR="$BASEDIR/secrets"

dropdb sthenauth && \
  createdb sthenauth && \
  rm -rf "$BASEDIR"

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
  server
