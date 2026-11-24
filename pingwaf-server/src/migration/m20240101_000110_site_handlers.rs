use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared("
            ALTER TABLE sites ADD COLUMN site_handler jsonb,
                ADD CONSTRAINT sites_handler_valid CHECK (site_handler IS NULL OR
                    (jsonb_typeof(site_handler)='object' AND site_handler ? 'kind'
                     AND coalesce(site_handler->>'kind','') IN ('redirect','static') AND ingress_port IS NOT NULL)),
                DROP CONSTRAINT sites_ingress_valid,
                ADD CONSTRAINT sites_ingress_valid CHECK (
                    ingress_port IS NULL AND ingress_protocol IS NULL OR
                    ingress_port IS NOT NULL AND ingress_port BETWEEN 1 AND 65535 AND ingress_protocol IS NOT NULL
                    AND ingress_protocol IN ('http','https') AND (
                        ingress_port NOT IN (80,443) OR site_handler IS NOT NULL AND (
                            ingress_port=80 AND ingress_protocol='http' OR ingress_port=443 AND ingress_protocol='https'
                        )
                    )
                );
            CREATE TRIGGER serialize_site_handler_write BEFORE UPDATE OF site_handler, additional_ingresses
                ON sites FOR EACH STATEMENT EXECUTE FUNCTION serialize_site_ingress_write();
        ").await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared("
            DO $$ BEGIN IF EXISTS(SELECT FROM sites WHERE site_handler IS NOT NULL) THEN
                RAISE EXCEPTION 'remove terminal site handlers before rollback'; END IF; END $$;
            DROP TRIGGER serialize_site_handler_write ON sites;
            ALTER TABLE sites DROP CONSTRAINT sites_ingress_valid, DROP COLUMN site_handler,
                ADD CONSTRAINT sites_ingress_valid CHECK (
                    ingress_port IS NULL AND ingress_protocol IS NULL OR
                    ingress_port IS NOT NULL AND ingress_port BETWEEN 1 AND 65535 AND ingress_port NOT IN (80,443)
                    AND ingress_protocol IS NOT NULL AND ingress_protocol IN ('http','https')
                );
        ").await?;
        Ok(())
    }
}
