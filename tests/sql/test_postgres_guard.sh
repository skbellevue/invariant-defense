#!/usr/bin/env bash
# Integration test for rules/sql/postgres_impact_guard.sql
# Usage: PGHOST=... PGUSER=<superuser> PGPASSWORD=... tests/sql/test_postgres_guard.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
DB="invariant_guard_test_$$"
export PGOPTIONS="-c client_min_messages=warning"
PSQL="psql -v ON_ERROR_STOP=1 -X -q"
expect_fail() {  # run SQL as app user, succeed only if it errors with an invariant message
  local sql="$1" label="$2"
  if out=$(PGUSER=inv_app PGPASSWORD=inv_app $PSQL -d "$DB" -c "$sql" 2>&1); then
    echo "FAIL: $label was allowed"; exit 1
  fi
  grep -q "invariant:" <<<"$out" || { echo "FAIL: $label errored without invariant message: $out"; exit 1; }
  echo "ok   blocked: $label"
}
expect_ok() {
  PGUSER=${3:-inv_app} PGPASSWORD=${4:-inv_app} $PSQL -d "$DB" -c "$1" >/dev/null || { echo "FAIL: $2"; exit 1; }
  echo "ok   allowed: $2"
}
$PSQL -d postgres -c "DROP ROLE IF EXISTS inv_app" -c "CREATE ROLE inv_app LOGIN PASSWORD 'inv_app'" -c "CREATE DATABASE $DB OWNER inv_app"
trap '$PSQL -d postgres -c "DROP DATABASE IF EXISTS $DB" >/dev/null; $PSQL -d postgres -c "DROP ROLE IF EXISTS inv_app" >/dev/null' EXIT
PGUSER=inv_app PGPASSWORD=inv_app $PSQL -d "$DB" -c "
  CREATE TABLE public.config_info (id serial PRIMARY KEY, data_id text, content text);
  INSERT INTO public.config_info (data_id, content) SELECT 'cfg-' || g, 'value ' || g FROM generate_series(1, 400) g;
  CREATE TABLE public.his_config_info (id serial PRIMARY KEY, content text);"
$PSQL -d "$DB" -f "$HERE/rules/sql/postgres_impact_guard.sql" >/dev/null
$PSQL -d "$DB" -c "SELECT invariant.protect('public.config_info'); SELECT invariant.protect('public.his_config_info');" >/dev/null

expect_ok "UPDATE config_info SET content = 'x' WHERE id <= 150" "150-row update (under limit)"
expect_fail "UPDATE config_info SET content = 'encrypted' WHERE id > 150" "mass update past 200 rows/window"
expect_fail "DELETE FROM config_info" "mass delete"
expect_fail "TRUNCATE config_info" "truncate of protected table"
expect_fail "DROP TABLE his_config_info" "drop of protected table"
expect_ok "SET invariant.break_glass = 'on'; UPDATE config_info SET content = 'maint'" "break-glass maintenance update"
expect_ok "SELECT count(*) FROM zz_payment_tokens_backup" "canary read (allowed, but logged)" inv_app inv_app
rows=$(PGUSER=inv_app PGPASSWORD=inv_app psql -X -t -A -d "$DB" -c "SELECT count(*) FROM config_info")
[ "$rows" = "400" ] || { echo "FAIL: expected 400 rows, got $rows"; exit 1; }
echo "ok   data intact: $rows rows"
echo "PASS postgres impact guard"
