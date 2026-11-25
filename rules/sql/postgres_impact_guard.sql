-- Invariant Defense - L5 impact guard for PostgreSQL (tested on PostgreSQL 16)
--
-- Makes database damage slow, visible and reversible:
--   1. mass UPDATE/DELETE on protected tables is rate-limited per database user
--   2. TRUNCATE of protected tables is blocked
--   3. DROP of protected tables is blocked (sql_drop event trigger aborts the transaction)
--   4. a canary table logs every row read through row-level security
--
-- Every block writes a line starting with "invariant:" to the server log
-- (RAISE LOG survives the rollback that RAISE EXCEPTION causes). Ship the log
-- to your SIEM and alert on it.
--
-- Break glass for planned maintenance, in the maintenance session only:
--   SET invariant.break_glass = 'on';
--
-- Requires superuser to install (event triggers). Superusers bypass RLS,
-- so the canary only watches application roles; that is the point: the
-- attacker usually arrives with the application's credentials.

CREATE SCHEMA IF NOT EXISTS invariant;

CREATE TABLE IF NOT EXISTS invariant.settings (
    key   text PRIMARY KEY,
    value text NOT NULL
);
INSERT INTO invariant.settings (key, value) VALUES
    ('mass_rows', '200'),      -- rows per user per table per window
    ('window_s', '120')
ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS invariant.protected_tables (
    table_name text PRIMARY KEY   -- unqualified or schema-qualified name
);

CREATE TABLE IF NOT EXISTS invariant.dml_ledger (
    ts       timestamptz NOT NULL DEFAULT clock_timestamp(),
    usename  text NOT NULL,
    tbl      text NOT NULL,
    op       text NOT NULL,
    rows     int  NOT NULL
);
CREATE INDEX IF NOT EXISTS dml_ledger_lookup ON invariant.dml_ledger (usename, tbl, ts);

CREATE OR REPLACE FUNCTION invariant.break_glass() RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT coalesce(current_setting('invariant.break_glass', true), 'off') = 'on'
$$;

-- 1. mass DML rate limit -----------------------------------------------------
CREATE OR REPLACE FUNCTION invariant.guard_mass_dml() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = invariant, pg_temp AS $$
DECLARE
    n     int;
    total int;
    lim   int;
    win   int;
BEGIN
    IF invariant.break_glass() THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        SELECT count(*) INTO n FROM new_rows;
    ELSE
        SELECT count(*) INTO n FROM old_rows;
    END IF;
    INSERT INTO invariant.dml_ledger (usename, tbl, op, rows)
    VALUES (session_user, TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, TG_OP, n);
    SELECT value::int INTO lim FROM invariant.settings WHERE key = 'mass_rows';
    SELECT value::int INTO win FROM invariant.settings WHERE key = 'window_s';
    SELECT coalesce(sum(rows), 0) INTO total
      FROM invariant.dml_ledger
     WHERE usename = session_user
       AND tbl = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME
       AND ts > clock_timestamp() - make_interval(secs => win);
    IF total > lim THEN
        RAISE LOG 'invariant: INV-L5-004 mass % blocked on %.% by % (% rows in % s, limit %)',
            TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME, session_user, total, win, lim;
        RAISE EXCEPTION 'invariant: % rows % on %.% by % within % s exceeds limit % (set invariant.break_glass for maintenance)',
            total, TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME, session_user, win, lim
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END
$$;

-- 2. TRUNCATE guard ------------------------------------------------------------
CREATE OR REPLACE FUNCTION invariant.guard_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF invariant.break_glass() THEN
        RETURN NULL;
    END IF;
    RAISE LOG 'invariant: INV-L5-003 TRUNCATE blocked on %.% by %', TG_TABLE_SCHEMA, TG_TABLE_NAME, session_user;
    RAISE EXCEPTION 'invariant: TRUNCATE of protected table %.% blocked', TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'P0001';
END
$$;

-- Attach guards 1 and 2 to a table and register it as protected.
CREATE OR REPLACE FUNCTION invariant.protect(tbl regclass) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    t text := tbl::text;
BEGIN
    INSERT INTO invariant.protected_tables VALUES (t) ON CONFLICT DO NOTHING;
    EXECUTE format('DROP TRIGGER IF EXISTS invariant_mass_update ON %s', t);
    EXECUTE format('DROP TRIGGER IF EXISTS invariant_mass_delete ON %s', t);
    EXECUTE format('DROP TRIGGER IF EXISTS invariant_truncate ON %s', t);
    EXECUTE format('CREATE TRIGGER invariant_mass_update AFTER UPDATE ON %s REFERENCING NEW TABLE AS new_rows '
                   'FOR EACH STATEMENT EXECUTE FUNCTION invariant.guard_mass_dml()', t);
    EXECUTE format('CREATE TRIGGER invariant_mass_delete AFTER DELETE ON %s REFERENCING OLD TABLE AS old_rows '
                   'FOR EACH STATEMENT EXECUTE FUNCTION invariant.guard_mass_dml()', t);
    EXECUTE format('CREATE TRIGGER invariant_truncate BEFORE TRUNCATE ON %s '
                   'FOR EACH STATEMENT EXECUTE FUNCTION invariant.guard_truncate()', t);
END
$$;

-- 3. DROP guard ----------------------------------------------------------------
CREATE OR REPLACE FUNCTION invariant.guard_drop() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = invariant, pg_temp AS $$
DECLARE
    obj record;
BEGIN
    IF invariant.break_glass() THEN
        RETURN;
    END IF;
    FOR obj IN SELECT * FROM pg_event_trigger_dropped_objects() WHERE object_type = 'table' LOOP
        IF EXISTS (SELECT 1 FROM invariant.protected_tables p
                    WHERE p.table_name IN (obj.object_identity, obj.object_name)) THEN
            RAISE LOG 'invariant: INV-L5-003 DROP blocked on % by %', obj.object_identity, session_user;
            RAISE EXCEPTION 'invariant: DROP of protected table % blocked', obj.object_identity
                USING ERRCODE = 'P0001';
        END IF;
    END LOOP;
END
$$;

DROP EVENT TRIGGER IF EXISTS invariant_guard_drop;
CREATE EVENT TRIGGER invariant_guard_drop ON sql_drop EXECUTE FUNCTION invariant.guard_drop();

-- 4. Canary table ---------------------------------------------------------------
-- No legitimate query reads this table. Name it like something an intruder wants.
CREATE OR REPLACE FUNCTION invariant.canary_touched(tbl text) RETURNS boolean
LANGUAGE plpgsql VOLATILE AS $$
BEGIN
    RAISE LOG 'invariant: INV-L5-001 canary table % read by % from %', tbl, session_user,
        coalesce(inet_client_addr()::text, 'local');
    RETURN true;
END
$$;

CREATE TABLE IF NOT EXISTS public.zz_payment_tokens_backup (
    id       serial PRIMARY KEY,
    customer text,
    token    text
);
INSERT INTO public.zz_payment_tokens_backup (customer, token)
SELECT 'customer-' || g, md5(random()::text) FROM generate_series(1, 5) g
WHERE NOT EXISTS (SELECT 1 FROM public.zz_payment_tokens_backup);
ALTER TABLE public.zz_payment_tokens_backup ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zz_payment_tokens_backup FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS invariant_canary ON public.zz_payment_tokens_backup;
CREATE POLICY invariant_canary ON public.zz_payment_tokens_backup
    USING (invariant.canary_touched('public.zz_payment_tokens_backup'));
SELECT invariant.protect('public.zz_payment_tokens_backup');
-- Make the bait reachable with application credentials; the policy logs every row read.
GRANT SELECT ON public.zz_payment_tokens_backup TO PUBLIC;

-- Guards run in the caller's context and need to see the invariant schema.
GRANT USAGE ON SCHEMA invariant TO PUBLIC;

-- Usage:
--   SELECT invariant.protect('public.config_info');
--   SELECT invariant.protect('public.his_config_info');
--   UPDATE invariant.settings SET value = '500' WHERE key = 'mass_rows';
--   -- prune the ledger daily:
--   DELETE FROM invariant.dml_ledger WHERE ts < now() - interval '1 day';
