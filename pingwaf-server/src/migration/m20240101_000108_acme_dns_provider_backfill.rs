//! Clear unused provider settings on legacy HTTP-01 orders.
//! Local DNS-01 orders using manual verification or an unrecognized provider
//! retain the original challenge and configuration until an administrator edits them.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Providers the managed API and the data plane both understand.
const SUPPORTED: &str =
    "'','manual','ali','aliyun','cf','cloudflare','tencent','dnspod','huawei','route53'";

fn backfill_sql(table: &str) -> String {
    format!(
        "UPDATE {table} \
         SET acme_dns_provider = NULL, acme_dns_config = NULL \
         WHERE lower(btrim(coalesce(acme_challenge_type, 'http-01'))) = 'http-01' \
           AND (lower(btrim(acme_dns_provider)) NOT IN ({SUPPORTED}) \
                OR lower(btrim(acme_dns_provider)) = 'route53')"
    )
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in ["site_certificates", "site_ssl"] {
            manager
                .get_connection()
                .execute_unprepared(&backfill_sql(table))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // A data backfill cannot be undone: the original provider string and
        // its credentials were never copied anywhere, and restoring them from
        // the code would invent configuration the operator did not choose.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, Database, TransactionTrait};

    #[tokio::test]
    #[ignore = "requires an isolated PostgreSQL database"]
    async fn acme_provider_backfill_postgres() {
        let db = Database::connect(std::env::var("PINGWAF_TEST_DATABASE_URL").unwrap())
            .await.unwrap();
        let txn = db.begin().await.unwrap();
        for table in ["site_certificates", "site_ssl"] {
            txn.execute_unprepared(&format!(
                "CREATE TEMP TABLE {table} (acme_challenge_type text, acme_dns_provider text, acme_dns_config jsonb);
                 INSERT INTO {table} VALUES
                   ('dns-01','manual','1'),('dns-01','','2'),('dns-01','legacy','3'),
                   ('dns-01','route53','4'),('http-01','legacy','5'),('http-01','route53','6');"
            )).await.unwrap();
        }
        Migration.up(&SchemaManager::new(&txn)).await.unwrap();
        for table in ["site_certificates", "site_ssl"] {
            let row = txn.query_one(sea_orm::Statement::from_string(
                txn.get_database_backend(),
                format!("SELECT count(*) FILTER (WHERE acme_challenge_type='dns-01' AND
                    (acme_dns_provider,acme_dns_config) IN (('manual','1'::jsonb),('','2'::jsonb),('legacy','3'::jsonb),('route53','4'::jsonb))) AS preserved,
                    count(*) FILTER (WHERE acme_challenge_type='http-01' AND acme_dns_provider IS NULL AND acme_dns_config IS NULL) AS cleared FROM {table}")
            )).await.unwrap().unwrap();
            assert_eq!(row.try_get::<i64>("", "preserved").unwrap(), 4, "{table}");
            assert_eq!(row.try_get::<i64>("", "cleared").unwrap(), 2, "{table}");
        }
        txn.rollback().await.unwrap();
    }
}
