use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared("
        CREATE TABLE syslog_settings(id integer PRIMARY KEY CHECK(id=1),revision bigint NOT NULL DEFAULT 0, config jsonb, ca text NOT NULL DEFAULT '', cert text NOT NULL DEFAULT '', sealed_key text NOT NULL DEFAULT '');
        INSERT INTO syslog_settings(id) VALUES(1);
        CREATE TABLE syslog_queue(seq bigserial PRIMARY KEY,event_id uuid NOT NULL UNIQUE,revision bigint NOT NULL,kind text NOT NULL, message bytea NOT NULL,created_at timestamptz NOT NULL DEFAULT now(), retry_at timestamptz NOT NULL DEFAULT now(), attempts integer NOT NULL DEFAULT 0);
        CREATE INDEX syslog_queue_created ON syslog_queue(created_at);
        CREATE TABLE syslog_queue_usage(id integer PRIMARY KEY CHECK(id=1), items bigint NOT NULL, bytes bigint NOT NULL);
        INSERT INTO syslog_queue_usage VALUES(1,0,0);
        CREATE FUNCTION syslog_update_usage() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE direction integer := CASE WHEN TG_OP='INSERT' THEN 1 ELSE -1 END;
        BEGIN
            UPDATE syslog_queue_usage SET items=items+direction*(SELECT count(*) FROM changed),
            bytes=bytes+direction*(SELECT COALESCE(sum(octet_length(message)),0) FROM changed) WHERE id=1;
            RETURN NULL;
        END $$;
        CREATE TRIGGER syslog_queue_add AFTER INSERT ON syslog_queue REFERENCING NEW TABLE AS changed
        FOR EACH STATEMENT EXECUTE FUNCTION syslog_update_usage();
        CREATE TRIGGER syslog_queue_remove AFTER DELETE ON syslog_queue REFERENCING OLD TABLE AS changed
        FOR EACH STATEMENT EXECUTE FUNCTION syslog_update_usage();").await?;
        Ok(())
    }
    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared("DROP TABLE syslog_queue; DROP FUNCTION syslog_update_usage(); DROP TABLE syslog_queue_usage; DROP TABLE syslog_settings;").await?;
        Ok(())
    }
}
