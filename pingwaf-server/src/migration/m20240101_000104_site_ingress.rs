//! Prepares the site storage for listener-scoped hostname claims. Custom
//! claims stay disabled until every configuration consumer can honor them.

use super::m20240101_000055_site_domain_unique as legacy;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP_SQL: &str = r#"
ALTER TABLE sites
    ADD COLUMN ingress_port integer,
    ADD COLUMN ingress_protocol text,
    ADD CONSTRAINT sites_ingress_valid CHECK (
        (ingress_port IS NULL AND ingress_protocol IS NULL) OR
        (ingress_port IS NOT NULL AND ingress_port BETWEEN 1 AND 65535
         AND ingress_port NOT IN (80, 443) AND ingress_protocol IS NOT NULL
         AND ingress_protocol COLLATE "C" IN ('http', 'https'))
    ),
    ADD CONSTRAINT sites_custom_ingress_disabled CHECK (ingress_port IS NULL);

CREATE INDEX idx_sites_ingress_domain ON sites (ingress_port, domain);

-- Internal transaction-ordering state, intentionally absent from backups.
CREATE TABLE site_ingress_write_guard (
    id integer PRIMARY KEY CHECK (id = 1), touched boolean NOT NULL
);
INSERT INTO site_ingress_write_guard VALUES (1, false);

CREATE FUNCTION serialize_site_ingress_write() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- A real update, not just a lock: an older snapshot must fail with 40001
    -- under Repeatable Read / Serializable, not validate against stale rows.
    UPDATE site_ingress_write_guard SET touched = NOT touched WHERE id = 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'site ingress write guard is missing';
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION site_ingress_hostname_valid(host text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT octet_length(host) <= 253 AND host COLLATE "C" ~
        '^(\*\.([a-z0-9_-]{1,63}\.)+)?[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*$'
$$;

CREATE FUNCTION site_ingress_hosts_overlap(a text, b text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT a COLLATE "C" = b COLLATE "C"
        OR (starts_with(a, '*.') AND right(b, length(a) - 1) COLLATE "C" = substring(a FROM 2) COLLATE "C")
        OR (starts_with(b, '*.') AND right(a, length(b) - 1) COLLATE "C" = substring(b FROM 2) COLLATE "C")
$$;

CREATE FUNCTION validate_site_ingress(candidate sites) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    hosts text[] := array_prepend(candidate.domain, candidate.alternate_domains);
    conflicting_site uuid;
BEGIN
    IF EXISTS (SELECT FROM unnest(hosts) AS host WHERE site_ingress_hostname_valid(host) IS NOT TRUE) THEN
        RAISE check_violation USING CONSTRAINT = 'sites_ingress_hostname_invalid',
            MESSAGE = 'invalid persisted site hostname', DETAIL = format('site %s', candidate.id);
    END IF;
    IF EXISTS (SELECT FROM unnest(hosts) AS host GROUP BY host COLLATE "C" HAVING count(*) > 1) THEN
        RAISE unique_violation USING CONSTRAINT = 'sites_ingress_domain_conflict',
            MESSAGE = 'domain already in use by this site', DETAIL = format('site %s', candidate.id);
    END IF;

    IF candidate.ingress_port IS NOT NULL AND EXISTS (
        SELECT FROM sites AS other WHERE other.id <> candidate.id
            AND other.ingress_port = candidate.ingress_port
            AND other.ingress_protocol COLLATE "C" <> candidate.ingress_protocol COLLATE "C"
    ) THEN
        RAISE unique_violation USING CONSTRAINT = 'sites_ingress_protocol_conflict',
            MESSAGE = 'site ingress port already uses another protocol';
    END IF;

    SELECT other.id INTO conflicting_site
    FROM sites AS other
    CROSS JOIN LATERAL unnest(array_prepend(other.domain, other.alternate_domains)) AS existing
    CROSS JOIN unnest(hosts) AS proposed
    WHERE other.id <> candidate.id
        AND ((candidate.ingress_port IS NULL AND other.ingress_port IS NULL)
            OR other.ingress_port = candidate.ingress_port)
        AND site_ingress_hosts_overlap(existing, proposed)
    LIMIT 1;
    IF FOUND THEN
        RAISE unique_violation USING CONSTRAINT = 'sites_ingress_domain_conflict',
            MESSAGE = 'domain already in use by another site',
            DETAIL = format('sites %s and %s', candidate.id, conflicting_site);
    END IF;
END $$;

-- ALTER TABLE holds the table lock through preflight and trigger replacement.
DO $$
DECLARE candidate sites;
BEGIN
    FOR candidate IN SELECT * FROM sites LOOP
        PERFORM validate_site_ingress(candidate);
    END LOOP;
END $$;

CREATE FUNCTION check_final_site_ingress() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE candidate sites;
BEGIN
    SELECT * INTO candidate FROM sites WHERE id = NEW.id;
    IF FOUND THEN
        PERFORM validate_site_ingress(candidate);
    END IF;
    RETURN NULL;
END $$;

DROP TRIGGER trg_site_domain_conflicts ON sites;
DROP FUNCTION check_site_domain_conflicts();
DROP INDEX uq_sites_domain;
-- 000002 also declared an inline UNIQUE, independent of the 000055 index.
ALTER TABLE sites DROP CONSTRAINT sites_domain_key;

CREATE TRIGGER serialize_site_ingress_write
    BEFORE INSERT OR DELETE OR UPDATE OF id, domain, alternate_domains, ingress_port, ingress_protocol
    ON sites FOR EACH STATEMENT EXECUTE FUNCTION serialize_site_ingress_write();

CREATE CONSTRAINT TRIGGER check_final_site_ingress
    AFTER INSERT OR UPDATE OF id, domain, alternate_domains, ingress_port, ingress_protocol
    ON sites DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_final_site_ingress();
"#;

const DOWN_SQL: &str = r#"
LOCK TABLE sites IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (SELECT FROM sites WHERE ingress_port IS NOT NULL OR ingress_protocol IS NOT NULL) THEN
        RAISE EXCEPTION 'remove or move all custom ingress sites before downgrading the schema';
    END IF;
END $$;
DROP TRIGGER check_final_site_ingress ON sites;
DROP TRIGGER serialize_site_ingress_write ON sites;
DROP FUNCTION check_final_site_ingress();
DROP FUNCTION validate_site_ingress(sites);
DROP FUNCTION site_ingress_hosts_overlap(text, text);
DROP FUNCTION site_ingress_hostname_valid(text);
DROP FUNCTION serialize_site_ingress_write();
DROP TABLE site_ingress_write_guard;
DROP INDEX idx_sites_ingress_domain;
ALTER TABLE sites DROP COLUMN ingress_port, DROP COLUMN ingress_protocol;
ALTER TABLE sites ADD CONSTRAINT sites_domain_key UNIQUE (domain);
"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(DOWN_SQL)
            .await?;
        legacy::Migration.up(manager).await
    }
}
