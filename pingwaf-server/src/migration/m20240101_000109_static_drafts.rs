use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared("
            CREATE TABLE static_drafts (
                id uuid PRIMARY KEY,
                owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                archive bytea NOT NULL CHECK (octet_length(archive) <= 8388608),
                digest text NOT NULL,
                expires_at timestamptz NOT NULL DEFAULT (now() + interval '24 hours')
            );
            CREATE INDEX static_drafts_owner ON static_drafts(owner_id);
            CREATE INDEX static_drafts_expiry ON static_drafts(expires_at);
        ").await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE static_drafts")
            .await?;
        Ok(())
    }
}
