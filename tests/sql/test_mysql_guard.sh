#!/usr/bin/env bash
# Integration test for rules/sql/mysql_impact_guard.sql (MySQL 8 / MariaDB)
# Usage: MYSQL="mysql -uroot -h127.0.0.1 -pPASS" tests/sql/test_mysql_guard.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
MYSQL=${MYSQL:-"mysql -uroot"}
DB="invariant_guard_test"
$MYSQL -e "DROP DATABASE IF EXISTS $DB; CREATE DATABASE $DB;"
trap '$MYSQL -e "DROP DATABASE IF EXISTS $DB"' EXIT
$MYSQL "$DB" -e "
  CREATE TABLE config_info (id INT AUTO_INCREMENT PRIMARY KEY, data_id VARCHAR(255), content TEXT);
  CREATE TABLE his_config_info (id INT AUTO_INCREMENT PRIMARY KEY, content TEXT);
  INSERT INTO config_info (data_id, content)
    WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < 400) SELECT CONCAT('cfg-', n), CONCAT('v', n) FROM s;"
$MYSQL "$DB" < "$HERE/rules/sql/mysql_impact_guard.sql"
$MYSQL "$DB" -e "UPDATE config_info SET content = 'x' WHERE id <= 150" && echo "ok   allowed: 150-row update"
if out=$($MYSQL "$DB" -e "UPDATE config_info SET content = 'enc' WHERE id > 150" 2>&1); then echo "FAIL: mass update allowed"; exit 1; fi
grep -q "invariant:" <<<"$out" && echo "ok   blocked: mass update (SQLSTATE 45000, invariant message)"
n=$($MYSQL -N "$DB" -e "SELECT COUNT(*) FROM config_info WHERE content = 'enc'")
[ "$n" = "0" ] || { echo "FAIL: partial update persisted ($n rows)"; exit 1; }
echo "ok   statement rolled back whole (0 rows changed)"
if $MYSQL "$DB" -e "DELETE FROM config_info" 2>/dev/null; then echo "FAIL: mass delete allowed"; exit 1; fi
echo "ok   blocked: mass delete"
$MYSQL "$DB" -e "SET @invariant_break_glass = 1; UPDATE config_info SET content = 'maint'" && echo "ok   allowed: break-glass maintenance"
echo "PASS mysql impact guard"
