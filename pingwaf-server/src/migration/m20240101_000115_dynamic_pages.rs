use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared("ALTER TABLE page_integrity_rules
            ADD COLUMN dynamic_stage text NOT NULL DEFAULT 'off' CHECK (dynamic_stage IN ('off','test','live')),
            ADD COLUMN dynamic_preview_digest text NOT NULL DEFAULT '',
            ADD COLUMN dynamic_region text NOT NULL DEFAULT '',
            ADD COLUMN dynamic_test_digest text NOT NULL DEFAULT ''").await?;
        Ok(())
    }
    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared("ALTER TABLE page_integrity_rules DROP COLUMN dynamic_stage, DROP COLUMN dynamic_region, DROP COLUMN dynamic_preview_digest, DROP COLUMN dynamic_test_digest").await?;
        Ok(())
    }
}
