//! Internal ordering state for consistent, per-node configuration snapshots.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TABLE managed_config_authority (
                    id integer PRIMARY KEY CHECK (id = 1),
                    epoch uuid NOT NULL
                 );
                 INSERT INTO managed_config_authority VALUES (1, gen_random_uuid());
                 CREATE TABLE managed_config_generations (
                    agent_id uuid PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
                    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
                    session_id uuid
                 );",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "DROP TABLE managed_config_generations;
                 DROP TABLE managed_config_authority;",
            )
            .await?;
        Ok(())
    }
}
