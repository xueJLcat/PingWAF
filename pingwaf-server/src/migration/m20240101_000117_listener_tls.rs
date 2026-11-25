//! Apply hostname-wide TLS constraints to additional HTTP listeners as well.
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(r#"
            ALTER FUNCTION validate_site_ingress_tls(uuid) RENAME TO validate_primary_ingress_tls;
            CREATE FUNCTION validate_site_ingress_tls(changed uuid) RETURNS void LANGUAGE plpgsql AS $$
            BEGIN
                PERFORM validate_primary_ingress_tls(changed);
                IF EXISTS (
                    SELECT FROM sites s JOIN site_ssl tls ON tls.site_id=s.id
                    WHERE s.id=changed AND tls.always_use_https
                      AND EXISTS (SELECT FROM unnest(s.additional_ingresses) entry WHERE entry LIKE 'http:%')
                ) THEN
                    RAISE check_violation USING CONSTRAINT='sites_ingress_https_redirect',
                        MESSAGE='additional HTTP ingress cannot redirect to HTTPS', DETAIL=changed::text;
                END IF;
                IF EXISTS (
                    SELECT FROM sites plain JOIN sites issuer ON plain.id=changed OR issuer.id=changed
                    JOIN site_ssl tls ON tls.site_id=issuer.id
                    CROSS JOIN LATERAL unnest(array_prepend(plain.domain, plain.alternate_domains)) p
                    CROSS JOIN LATERAL unnest(array_prepend(issuer.domain, issuer.alternate_domains)) h
                    WHERE tls.hsts_enabled AND site_ingress_hosts_overlap(p,h)
                      AND EXISTS (SELECT FROM unnest(plain.additional_ingresses) entry WHERE entry LIKE 'http:%')
                ) THEN
                    RAISE check_violation USING CONSTRAINT='sites_ingress_hsts_conflict',
                        MESSAGE='HSTS overlaps an additional HTTP ingress hostname', DETAIL=changed::text;
                END IF;
            END $$;
            CREATE CONSTRAINT TRIGGER check_extra_ingress_tls AFTER UPDATE OF additional_ingresses
                ON sites DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_final_site_ingress_tls();
            SELECT validate_site_ingress_tls(id) FROM sites WHERE cardinality(additional_ingresses)>0;
        "#).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared("
            DROP TRIGGER check_extra_ingress_tls ON sites;
            DROP FUNCTION validate_site_ingress_tls(uuid);
            ALTER FUNCTION validate_primary_ingress_tls(uuid) RENAME TO validate_site_ingress_tls;
        ").await?;
        Ok(())
    }
}
