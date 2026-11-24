use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared("
            CREATE TABLE page_integrity_rules (
                id uuid PRIMARY KEY, site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                path text NOT NULL CHECK (left(path,1)='/' AND octet_length(path)<=2048),
                mode text NOT NULL DEFAULT 'alert' CHECK (mode IN ('alert','trusted_copy')),
                candidate_digest text, candidate_body bytea, candidate_type text,
                candidate_at timestamptz, active_version bigint,
                UNIQUE(site_id,path),
                CHECK ((candidate_digest IS NULL)=(candidate_body IS NULL)),
                CHECK ((candidate_type IS NULL)=(candidate_body IS NULL)),
                CHECK (candidate_digest ~ '^[a-f0-9]{64}$' AND octet_length(candidate_body)<=524288)
            );
            CREATE TABLE page_integrity_versions (
                rule_id uuid NOT NULL REFERENCES page_integrity_rules(id) ON DELETE CASCADE,
                version bigint NOT NULL, digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),
                content_type text NOT NULL, body bytea NOT NULL CHECK(octet_length(body)<=524288),
                approved_by uuid NOT NULL, approved_at timestamptz NOT NULL DEFAULT now(),
                PRIMARY KEY(rule_id,version)
            );
            ALTER TABLE page_integrity_rules ADD FOREIGN KEY(id,active_version)
                REFERENCES page_integrity_versions(rule_id,version) DEFERRABLE INITIALLY DEFERRED;
            CREATE TABLE page_integrity_events (
                rule_id uuid NOT NULL REFERENCES page_integrity_rules(id) ON DELETE CASCADE,
                category text NOT NULL, detail text NOT NULL, first_seen timestamptz NOT NULL DEFAULT now(),
                last_seen timestamptz NOT NULL DEFAULT now(), last_notified timestamptz, observations bigint NOT NULL DEFAULT 1,
                PRIMARY KEY(rule_id,category,detail)
            );
        ").await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(
            "DROP TABLE page_integrity_events, page_integrity_versions, page_integrity_rules",
        ).await?;
        Ok(())
    }
}
