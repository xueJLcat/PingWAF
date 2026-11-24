//! Serialize TLS posture and hostname changes that can make an HTTP ingress unreachable.
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"
CREATE FUNCTION validate_site_ingress_tls(changed uuid) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT FROM sites s JOIN site_ssl tls ON tls.site_id = s.id
        WHERE s.id = changed AND s.ingress_protocol = 'http' AND tls.always_use_https
    ) THEN
        RAISE check_violation USING CONSTRAINT = 'sites_ingress_https_redirect',
            MESSAGE = 'custom HTTP ingress cannot redirect to HTTPS';
    END IF;
    IF EXISTS (
        SELECT FROM sites plain
        JOIN sites issuer ON plain.id = changed OR issuer.id = changed
        JOIN site_ssl tls ON tls.site_id = issuer.id
        CROSS JOIN LATERAL unnest(array_prepend(plain.domain, plain.alternate_domains)) p
        CROSS JOIN LATERAL unnest(array_prepend(issuer.domain, issuer.alternate_domains)) h
        WHERE plain.ingress_protocol = 'http' AND tls.hsts_enabled
          AND site_ingress_hosts_overlap(p,h)
    ) THEN
        RAISE check_violation USING CONSTRAINT = 'sites_ingress_hsts_conflict',
            MESSAGE = 'HSTS overlaps a custom HTTP ingress hostname';
    END IF;
END $$;

CREATE FUNCTION check_final_site_ingress_tls() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'sites' THEN
        PERFORM validate_site_ingress_tls(NEW.id);
    ELSE
        PERFORM validate_site_ingress_tls(NEW.site_id);
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER serialize_ingress_tls_write
    BEFORE INSERT OR DELETE OR UPDATE OF site_id, hsts_enabled, always_use_https
    ON site_ssl FOR EACH STATEMENT EXECUTE FUNCTION serialize_site_ingress_write();

CREATE CONSTRAINT TRIGGER check_ingress_tls_site
    AFTER INSERT OR UPDATE OF domain, alternate_domains, ingress_port, ingress_protocol
    ON sites DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_final_site_ingress_tls();
CREATE CONSTRAINT TRIGGER check_ingress_tls_posture
    AFTER INSERT OR UPDATE OF site_id, hsts_enabled, always_use_https
    ON site_ssl DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_final_site_ingress_tls();

SELECT validate_site_ingress_tls(id) FROM sites WHERE ingress_protocol = 'http';
"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "DROP TRIGGER check_ingress_tls_posture ON site_ssl;
             DROP TRIGGER check_ingress_tls_site ON sites;
             DROP TRIGGER serialize_ingress_tls_write ON site_ssl;
             DROP FUNCTION check_final_site_ingress_tls();
             DROP FUNCTION validate_site_ingress_tls(uuid);",
            )
            .await?;
        Ok(())
    }
}
