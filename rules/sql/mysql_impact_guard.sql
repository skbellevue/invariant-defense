-- Invariant Defense - L5 impact guard for MySQL 8 / MariaDB 10.6+ (tested on MariaDB)
--
-- Nacos usually stores configuration in MySQL. JADEPUFFER encrypted ~1,342
-- config_info rows and dropped the originals. This script:
--   1. rate-limits UPDATE/DELETE on protected tables per database user (per-row
--      trigger + 10-second buckets; a blocked statement is rolled back whole)
--   2. documents the privilege changes that stop DROP/TRUNCATE (MySQL triggers
--      cannot intercept DDL)
--
-- Alerting: the blocked statement fails with SQLSTATE 45000 and a message that
-- starts with "invariant:". Capture it with your audit plugin (MariaDB
-- server_audit, MySQL Enterprise Audit, Percona audit_log) or application logs.
--
-- Break glass for maintenance, in that session only:  SET @invariant_break_glass = 1;
--
-- Run inside the Nacos database:  mysql nacos < mysql_impact_guard.sql

CREATE TABLE IF NOT EXISTS invariant_settings (
    k VARCHAR(64) PRIMARY KEY,
    v VARCHAR(64) NOT NULL
) ENGINE=InnoDB;
INSERT IGNORE INTO invariant_settings (k, v) VALUES ('mass_rows', '200'), ('window_s', '120');

CREATE TABLE IF NOT EXISTS invariant_dml_ledger (
    usr    VARCHAR(128) NOT NULL,
    tbl    VARCHAR(128) NOT NULL,
    bucket BIGINT       NOT NULL,
    rows_n INT          NOT NULL DEFAULT 0,
    PRIMARY KEY (usr, tbl, bucket)
) ENGINE=InnoDB;

DROP PROCEDURE IF EXISTS invariant_count;
DELIMITER //
CREATE PROCEDURE invariant_count(IN p_tbl VARCHAR(128))
proc: BEGIN
    DECLARE lim INT DEFAULT 200;
    DECLARE win INT DEFAULT 120;
    DECLARE total INT DEFAULT 0;
    DECLARE b BIGINT;
    DECLARE who VARCHAR(128);
    IF COALESCE(@invariant_break_glass, 0) = 1 THEN
        LEAVE proc;
    END IF;
    SELECT CAST(v AS SIGNED) INTO lim FROM invariant_settings WHERE k = 'mass_rows';
    SELECT CAST(v AS SIGNED) INTO win FROM invariant_settings WHERE k = 'window_s';
    SET who = SUBSTRING_INDEX(USER(), '@', 1);
    SET b = UNIX_TIMESTAMP() DIV 10;
    INSERT INTO invariant_dml_ledger (usr, tbl, bucket, rows_n) VALUES (who, p_tbl, b, 1)
        ON DUPLICATE KEY UPDATE rows_n = rows_n + 1;
    SELECT COALESCE(SUM(rows_n), 0) INTO total FROM invariant_dml_ledger
     WHERE usr = who AND tbl = p_tbl AND bucket > b - (win DIV 10);
    IF total > lim THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'invariant: INV-L5-004 mass modification blocked by rate limit (SET @invariant_break_glass=1 for maintenance)';
    END IF;
END //
DELIMITER ;

-- Protect Nacos tables (repeat for any table you care about).
DROP TRIGGER IF EXISTS invariant_config_info_bu;
DROP TRIGGER IF EXISTS invariant_config_info_bd;
DROP TRIGGER IF EXISTS invariant_his_config_info_bd;
CREATE TRIGGER invariant_config_info_bu BEFORE UPDATE ON config_info FOR EACH ROW CALL invariant_count('config_info');
CREATE TRIGGER invariant_config_info_bd BEFORE DELETE ON config_info FOR EACH ROW CALL invariant_count('config_info');
CREATE TRIGGER invariant_his_config_info_bd BEFORE DELETE ON his_config_info FOR EACH ROW CALL invariant_count('his_config_info');

-- DDL cannot be trapped by triggers: remove the privilege instead. The Nacos runtime
-- account needs SELECT/INSERT/UPDATE/DELETE only; keep DROP/ALTER for a separate
-- migration account used through change management.
--   REVOKE DROP, ALTER, INDEX, CREATE ON nacos.* FROM 'nacos'@'%';
--   GRANT SELECT, INSERT, UPDATE, DELETE ON nacos.* TO 'nacos'@'%';
-- Prune the ledger periodically:
--   DELETE FROM invariant_dml_ledger WHERE bucket < UNIX_TIMESTAMP() DIV 10 - 8640;
