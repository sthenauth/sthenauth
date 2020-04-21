#!/bin/sh

################################################################################
set -e
set -u
set -x

################################################################################
exec 1>&2

################################################################################
PORT=${PORT:-3001}
PASSWORD="ooYuBezoo2EiwaeciCha"

################################################################################
export STHENAUTH_DB="${STHENAUTH_DB:-dbname=sthenauth}"
export STHENAUTH_SECRETS_DIR="${STHENAUTH_SECRETS_DIR:-/tmp/sthenauth}"

################################################################################
_curl() {
  path=$1
  shift

  curl --verbose --ipv4 --cacert /tmp/chain.pem --fail \
    "$@" "https://localhost:${PORT}/auth/$path"
}

################################################################################
get() {
  path=$1
  shift

  _curl "$path" "$@"
}

################################################################################
post() {
  path=$1
  shift

  _curl "$path" \
    --header 'Content-Type: application/json' \
    --data @- "$@"
}

################################################################################
gen_names() {
  for n in $(seq 1 10); do
    echo "example$n@example.com"
  done
}

################################################################################
make_login_json() {
  name=$1
  pass=$PASSWORD
  [ $# -eq 2 ] && pass=$2
  cat <<EOF
{"name": "$name", "password": "$pass"}
EOF
}

################################################################################
setup() {
  sthenauth --email admin@example.com --password "$PASSWORD" init
  sthenauth --email admin@example.com --password "$PASSWORD" policy mode --self-service

  # Store the server's certificate chain for cURL:
  echo | \
    openssl s_client --connect localhost:"${PORT}" -showcerts | \
    sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /tmp/chain.pem

  for name in $(gen_names); do
    make_login_json "$name" | post create
  done
}

################################################################################
test_accounts_do_not_have_admin() {
  for name in $(gen_names); do
    if sthenauth --email "$name" --password "$PASSWORD" info; then
      >&2 echo "FAIL: account $name has admin!!"
      exit 1
    fi
  done
}

################################################################################
test_can_login_with_password() {
  for name in $(gen_names); do
    make_login_json "$name" | post login
  done
}

################################################################################
test_failed_login_with_bad_password() {
  for name in $(gen_names); do
    if make_login_json "$name" "${PASSWORD}ABC" | post login; then
      >&2 echo "FAIL: login for $name should have failed!!"
      exit 1
    fi
  done
}

################################################################################
test_no_accounts_without_self_service() {
  pass="Woh6zeejeb9phaiD0che"
  name="${pass}@example.com"

  sthenauth --email admin@example.com --password "$PASSWORD" policy mode --admin-invite

  if make_login_json "$name" "$pass" | post login; then
    >&2 echo "FAIL: should not have been able to create account"
    exit 1
  fi

  sthenauth --email admin@example.com --password "$PASSWORD" policy mode --self-service
}

################################################################################
test_gain_access_with_session_cookie() {
  name="example1@example.com"

  make_login_json "$name" | post login --cookie-jar /tmp/cookies
  get session --cookie /tmp/cookies

  # And fails without session cookie
  if get session; then
    >&2 echo "FAIL: getting session without cookie should fail"
    exit 1
  fi
}

################################################################################
# Tests:
setup

test_accounts_do_not_have_admin
test_can_login_with_password
test_failed_login_with_bad_password
test_no_accounts_without_self_service
test_gain_access_with_session_cookie
