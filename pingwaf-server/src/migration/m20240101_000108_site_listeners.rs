use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(r#"
            ALTER TABLE sites ADD COLUMN additional_ingresses text[] NOT NULL DEFAULT '{}';
            CREATE FUNCTION site_listener_claims(primary_port integer, primary_protocol text, extras text[])
            RETURNS TABLE (port integer, protocol text) LANGUAGE sql IMMUTABLE AS $$
                SELECT primary_port, primary_protocol WHERE primary_port IS NOT NULL
                UNION ALL SELECT 80, 'http' WHERE primary_port IS NULL
                UNION ALL SELECT 443, 'https' WHERE primary_port IS NULL
                UNION ALL SELECT split_part(v, ':', 2)::integer, split_part(v, ':', 1)
                    FROM unnest(extras) v
            $$;
            CREATE FUNCTION check_site_listener_set() RETURNS trigger LANGUAGE plpgsql AS $$
            DECLARE s sites;
            BEGIN
                SELECT * INTO s FROM sites WHERE id = NEW.id;
                IF NOT FOUND THEN RETURN NULL; END IF;
                IF cardinality(s.additional_ingresses) >= 32 OR
                   EXISTS (SELECT FROM unnest(s.additional_ingresses) v WHERE
                       v IS NULL OR v COLLATE "C" !~ '^(http|https):[1-9][0-9]{0,4}$') THEN
                    RAISE check_violation USING CONSTRAINT = 'sites_ingress_valid';
                END IF;
                IF EXISTS (SELECT FROM site_listener_claims(s.ingress_port,s.ingress_protocol,s.additional_ingresses) c GROUP BY c.port
                           HAVING count(*) > 1 OR c.port > 65535) THEN
                    RAISE check_violation USING CONSTRAINT = 'sites_ingress_valid';
                END IF;
                IF EXISTS (SELECT FROM sites o, site_listener_claims(o.ingress_port,o.ingress_protocol,o.additional_ingresses) a, site_listener_claims(s.ingress_port,s.ingress_protocol,s.additional_ingresses) b
                           WHERE o.id <> s.id AND a.port = b.port AND a.protocol <> b.protocol) THEN
                    RAISE unique_violation USING CONSTRAINT = 'sites_ingress_protocol_conflict';
                END IF;
                IF EXISTS (SELECT FROM sites o, site_listener_claims(o.ingress_port,o.ingress_protocol,o.additional_ingresses) a, site_listener_claims(s.ingress_port,s.ingress_protocol,s.additional_ingresses) b,
                           unnest(array_prepend(s.domain, s.alternate_domains)) x,
                           unnest(array_prepend(o.domain, o.alternate_domains)) y
                           WHERE o.id <> s.id AND a.port = b.port AND site_ingress_hosts_overlap(x,y)) THEN
                    RAISE unique_violation USING CONSTRAINT = 'sites_ingress_domain_conflict';
                END IF;
                RETURN NULL;
            END $$;
            CREATE TRIGGER serialize_additional_ingress BEFORE UPDATE OF additional_ingresses ON sites
                FOR EACH STATEMENT EXECUTE FUNCTION serialize_site_ingress_write();
            CREATE CONSTRAINT TRIGGER check_site_listener_set AFTER INSERT OR UPDATE OF
                id, domain, alternate_domains, ingress_port, ingress_protocol, additional_ingresses ON sites
                DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_site_listener_set();
        "#).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(r#"
            LOCK TABLE sites IN ACCESS EXCLUSIVE MODE;
            DO $$ BEGIN IF EXISTS (SELECT FROM sites WHERE cardinality(additional_ingresses) > 0)
                THEN RAISE EXCEPTION 'remove additional site listeners before downgrade'; END IF; END $$;
            DROP TRIGGER check_site_listener_set ON sites;
            DROP TRIGGER serialize_additional_ingress ON sites;
            DROP FUNCTION check_site_listener_set();
            DROP FUNCTION site_listener_claims(integer,text,text[]);
            ALTER TABLE sites DROP COLUMN additional_ingresses;
        "#).await?;
        Ok(())
    }
}
