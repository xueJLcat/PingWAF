//! Open custom site writes after applying the hostname, session and TLS migrations.
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(
            "ALTER TABLE sites DROP CONSTRAINT sites_custom_ingress_disabled"
        ).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // PostgreSQL validates all rows under the ALTER TABLE lock. Existing
        // custom sites make the downgrade fail atomically with their data intact.
        manager.get_connection().execute_unprepared(
            "ALTER TABLE sites ADD CONSTRAINT sites_custom_ingress_disabled CHECK (ingress_port IS NULL)"
        ).await?;
        Ok(())
    }
}
