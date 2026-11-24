use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared("
          CREATE TABLE protection_reports (
            id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            selection jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
            status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','ready','failed')),
            error text, snapshot jsonb, pdf bytea, csv bytea, lease uuid, lease_until timestamptz,
            expires_at timestamptz NOT NULL DEFAULT now()+interval '7 days'
          );
          CREATE INDEX protection_reports_owner ON protection_reports(owner_id,created_at DESC);
          CREATE INDEX protection_reports_queue ON protection_reports(created_at) WHERE status IN ('queued','running');
          CREATE TABLE report_coverage (
            minute timestamptz NOT NULL, site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
            samples integer NOT NULL, PRIMARY KEY(site_id,minute)
          );
          CREATE INDEX report_coverage_expiry ON report_coverage(minute);
        ").await?;
        Ok(())
    }
    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared("DROP TABLE report_coverage,protection_reports")
            .await?;
        Ok(())
    }
}
