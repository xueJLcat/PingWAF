use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared("
            ALTER TABLE static_drafts ADD COLUMN preview_hash text, ADD COLUMN preview_until timestamptz;
            CREATE TABLE static_releases (
                site_id uuid REFERENCES sites(id) ON DELETE CASCADE,
                digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
                archive bytea NOT NULL CHECK (octet_length(archive) BETWEEN 1 AND 8388608),
                published_at timestamptz NOT NULL DEFAULT now(),
                PRIMARY KEY(site_id, digest)
            );
            ALTER TABLE sites DROP CONSTRAINT sites_handler_valid,
                ADD CONSTRAINT sites_handler_valid CHECK (site_handler IS NULL OR
                    (jsonb_typeof(site_handler)='object' AND site_handler ? 'kind'
                     AND coalesce(site_handler->>'kind','') IN ('redirect','static','zip') AND ingress_port IS NOT NULL));
        ").await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared("
            DO $$ BEGIN IF EXISTS (SELECT FROM static_releases) THEN
                RAISE EXCEPTION 'remove uploaded site versions before downgrade'; END IF; END $$;
            ALTER TABLE sites DROP CONSTRAINT sites_handler_valid,
                ADD CONSTRAINT sites_handler_valid CHECK (site_handler IS NULL OR
                    (jsonb_typeof(site_handler)='object' AND site_handler ? 'kind'
                     AND coalesce(site_handler->>'kind','') IN ('redirect','static') AND ingress_port IS NOT NULL));
            DROP TABLE static_releases;
            ALTER TABLE static_drafts DROP COLUMN preview_hash, DROP COLUMN preview_until;
        ").await?;
        Ok(())
    }
}
