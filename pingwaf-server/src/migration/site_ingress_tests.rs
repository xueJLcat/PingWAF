//! Real PostgreSQL regression. Only run against a fresh disposable database.

use super::*;
use crate::{config_catalog, config_restore};
use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction,
    DbBackend, IsolationLevel, RuntimeErr, Statement, TransactionTrait,
};
use std::time::Duration;

const USER: &str = "00000000-0000-0000-0000-000000000001";

fn legacy_insert(domain: &str) -> String {
    format!(
        "INSERT INTO sites (id, user_id, name, domain, created_at, updated_at) \
         VALUES (gen_random_uuid(), '{USER}', 'test', '{domain}', now(), now())"
    )
}

fn insert(domain: &str, aliases: &str, port: i32, protocol: &str) -> String {
    format!(
        "INSERT INTO sites (id, user_id, name, domain, alternate_domains, \
         ingress_port, ingress_protocol, created_at, updated_at) VALUES \
         (gen_random_uuid(), '{USER}', 'test', '{domain}', '{aliases}', \
          {port}, '{protocol}', now(), now())"
    )
}

fn assert_db_error(error: &DbErr, code: &str, constraint: Option<&str>) {
    let (DbErr::Exec(RuntimeErr::SqlxError(sea_orm::sqlx::Error::Database(
        pg,
    )))
    | DbErr::Query(RuntimeErr::SqlxError(sea_orm::sqlx::Error::Database(
        pg,
    )))) = error
    else {
        panic!("expected PostgreSQL error, got {error:?}");
    };
    assert_eq!(pg.code().as_deref(), Some(code), "{pg:?}");
    assert_eq!(pg.constraint(), constraint, "{pg:?}");
}

async fn scalar<T: sea_orm::TryGetable>(
    db: &impl ConnectionTrait,
    sql: &str,
) -> T {
    db.query_one(Statement::from_string(DbBackend::Postgres, sql))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index(0)
        .unwrap()
}

async fn contender(
    txn: DatabaseTransaction,
    sql: String,
) -> (bool, Result<(), DbErr>) {
    if let Err(error) = txn.execute_unprepared(&sql).await {
        txn.rollback().await.unwrap();
        return (false, Err(error));
    }
    (true, txn.commit().await)
}

async fn race(
    db: &DatabaseConnection,
    isolation: IsolationLevel,
    first: String,
    second: String,
    expected_constraint: Option<&str>,
) {
    db.execute_unprepared("DELETE FROM sites").await.unwrap();
    let winner = db.begin_with_config(Some(isolation), None).await.unwrap();
    winner.execute_unprepared(&first).await.unwrap();
    let waiter = db.begin_with_config(Some(isolation), None).await.unwrap();
    assert_eq!(
        scalar::<i64>(&waiter, "SELECT count(*) FROM sites").await,
        0
    );
    let pid: i32 = scalar(&waiter, "SELECT pg_backend_pid()").await;
    let job = tokio::spawn(contender(waiter, second.clone()));
    tokio::time::timeout(Duration::from_secs(5), async {
        let blocking =
            format!("SELECT cardinality(pg_blocking_pids({pid})) > 0");
        while !scalar::<bool>(db, &blocking).await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the second write must wait for the guard row");
    if expected_constraint.is_some() {
        winner.commit().await.unwrap();
    } else {
        winner.rollback().await.unwrap();
    }
    let (inserted, result) = tokio::time::timeout(Duration::from_secs(5), job)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(scalar::<i64>(db, "SELECT count(*) FROM sites").await, 1);
    match expected_constraint {
        None => {
            assert!(inserted);
            result.unwrap();
        },
        Some(constraint)
            if matches!(isolation, IsolationLevel::ReadCommitted) =>
        {
            assert!(inserted, "conflict must be checked at commit");
            let error = result.unwrap_err();
            assert_db_error(&error, "23505", Some(constraint));
            if constraint == "sites_ingress_domain_conflict" {
                let error = crate::api::sites::map_site_domain_conflict(error);
                assert_eq!(error.code(), "site.domain_conflict");
                assert_eq!(
                    axum::response::IntoResponse::into_response(error).status(),
                    axum::http::StatusCode::BAD_REQUEST,
                );
            }
        },
        Some(constraint) => {
            assert!(!inserted);
            assert_db_error(&result.unwrap_err(), "40001", None);
            assert_db_error(
                &db.execute_unprepared(&second).await.unwrap_err(),
                "23505",
                Some(constraint),
            );
        },
    }
}

#[tokio::test]
#[ignore = "requires PINGWAF_TEST_DATABASE_URL pointing at a fresh disposable PostgreSQL database"]
async fn site_ingress_migration_postgres() {
    let url = std::env::var("PINGWAF_TEST_DATABASE_URL").unwrap();
    let db = Database::connect(url).await.unwrap();
    assert!(scalar::<bool>(&db, "SELECT to_regclass('sites') IS NULL AND to_regclass('seaql_migrations') IS NULL").await);
    Migrator::up(&db, Some(103)).await.unwrap();
    db.execute_unprepared(&format!(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ('{USER}', 'owner@example.test', 'irrelevant', now(), now())"
    ))
    .await
    .unwrap();
    for (bad, code, constraint) in [
        ("APP.test", "23514", "sites_ingress_hostname_invalid"),
        ("inside.app.test", "23505", "sites_ingress_domain_conflict"),
    ] {
        db.execute_unprepared(&legacy_insert("*.app.test"))
            .await
            .unwrap();
        db.execute_unprepared(&legacy_insert(bad)).await.unwrap();
        assert_db_error(
            &Migrator::up(&db, None).await.unwrap_err(),
            code,
            Some(constraint),
        );
        assert!(scalar::<bool>(&db, "SELECT to_regclass('uq_sites_domain') IS NOT NULL AND to_regclass('site_ingress_write_guard') IS NULL").await);
        db.execute_unprepared("DELETE FROM sites").await.unwrap();
    }

    db.execute_unprepared(&legacy_insert("app.test"))
        .await
        .unwrap();
    Migrator::up(&db, None).await.unwrap();
    assert_eq!(scalar::<i64>(&db, "SELECT count(*) FROM sites WHERE ingress_port IS NULL AND ingress_protocol IS NULL").await, 1);
    let scope = config_catalog::VersionScope::Deployment;
    let legacy_snapshot =
        config_catalog::capture(&db, scope, true).await.unwrap();
    let legacy_site = &legacy_snapshot["tables"]["sites"][0];
    assert!(legacy_site.is_object());
    assert!(legacy_site.get("ingress_port").is_none());
    assert!(legacy_site.get("ingress_protocol").is_none());
    assert_db_error(
        &db.execute_unprepared(&insert("app.test", "{}", 81, "http"))
            .await
            .unwrap_err(),
        "23514",
        Some("sites_custom_ingress_disabled"),
    );
    db.execute_unprepared(
        "ALTER TABLE sites DROP CONSTRAINT sites_custom_ingress_disabled",
    )
    .await
    .unwrap();

    for port in [81, 82, 83] {
        db.execute_unprepared(&insert("app.test", "{}", port, "http"))
            .await
            .unwrap();
    }
    assert_eq!(
        scalar::<i64>(
            &db,
            "SELECT count(*) FROM sites WHERE domain = 'app.test'"
        )
        .await,
        4
    );
    let state = crate::api::state::AppState::new(
        db.clone(),
        crate::config::ServerConfig::default(),
        crate::grpc::AgentRegistry::new(),
    );
    crate::api::sites::check_ingress_writes(&state, USER.parse().unwrap())
        .await;
    let owner = crate::mcp::tools::ToolContext {
        state: &state,
        actor: "regression",
        can_write: true,
        subject: USER.parse().unwrap(),
        is_admin: false,
    };
    let args = serde_json::json!({"domain":"app.test","status":"paused"});
    let write = |ctx| crate::mcp::tools::call(ctx, "set_site_status", &args);
    assert!(write(&owner).await.unwrap_err().contains("multiple sites"));
    let stranger = crate::mcp::tools::ToolContext {
        subject: uuid::Uuid::new_v4(),
        ..owner
    };
    assert_eq!(write(&stranger).await.unwrap_err(), "site not found");
    let listed =
        crate::mcp::tools::call(&owner, "list_sites", &serde_json::json!({}))
            .await
            .unwrap();
    let rows = listed["sites"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let explicit = rows.iter().find(|site| site["ingress_port"] == 82).unwrap();
    assert_eq!(explicit["ingress_protocol"], "http");
    assert!(rows.iter().any(|site| serde_json::Value::is_null(
        &site["ingress_port"]
    ) && serde_json::Value::is_null(
        &site["ingress_protocol"]
    )));
    for invalid in [
        "ingress_protocol = NULL",
        "ingress_port = NULL",
        "ingress_port = 443",
        "ingress_port = 65536",
        "ingress_protocol = 'HTTP'",
    ] {
        assert_db_error(
            &db.execute_unprepared(&format!(
                "UPDATE sites SET {invalid} WHERE ingress_port = 81"
            ))
            .await
            .unwrap_err(),
            "23514",
            Some("sites_ingress_valid"),
        );
    }
    db.execute_unprepared(&insert("*.app.test", "{}", 81, "http"))
        .await
        .unwrap();
    db.execute_unprepared(&insert("notapp.test", "{}", 81, "http"))
        .await
        .unwrap();
    crate::grpc::check_legacy_ingress_delivery(&db, USER).await;
    let a: String = scalar(&db, "SELECT id::text FROM sites WHERE domain='app.test' AND ingress_port=81").await;
    let b: String = scalar(&db, "SELECT id::text FROM sites WHERE domain='app.test' AND ingress_port=82").await;
    let tx = db.begin().await.unwrap();
    tx.execute_unprepared(&format!(
        "UPDATE sites SET ingress_port=82 WHERE id='{a}'"
    ))
    .await
    .unwrap();
    tx.execute_unprepared(&format!(
        "UPDATE sites SET ingress_port=81 WHERE id='{b}'"
    ))
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        scalar::<i32>(
            &db,
            &format!("SELECT ingress_port FROM sites WHERE id='{a}'")
        )
        .await,
        82
    );
    let mut snapshot = config_catalog::capture(&db, scope, true).await.unwrap();
    for row in snapshot["tables"]["sites"].as_array_mut().unwrap() {
        if row["id"] == a {
            row["ingress_port"] = 81.into();
        } else if row["id"] == b {
            row["ingress_port"] = 82.into();
        }
    }
    let tx = db.begin().await.unwrap();
    let plan = config_restore::prepare_restore(
        &tx,
        scope,
        &snapshot,
        config_restore::RestoreOptions::default(),
    )
    .await
    .unwrap();
    config_restore::apply_restore(&tx, plan).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        scalar::<i32>(
            &db,
            &format!("SELECT ingress_port FROM sites WHERE id='{a}'")
        )
        .await,
        81
    );
    assert_eq!(
        scalar::<i32>(
            &db,
            &format!("SELECT ingress_port FROM sites WHERE id='{b}'")
        )
        .await,
        82
    );

    Migrator::down(&db, Some(1)).await.unwrap();
    assert!(Migrator::down(&db, Some(1))
        .await
        .unwrap_err()
        .to_string()
        .contains("custom ingress sites"));
    assert_eq!(
        scalar::<i64>(
            &db,
            "SELECT count(*) FROM sites WHERE ingress_port IS NOT NULL"
        )
        .await,
        5
    );
    for level in [
        IsolationLevel::ReadCommitted,
        IsolationLevel::RepeatableRead,
        IsolationLevel::Serializable,
    ] {
        let domain = "sites_ingress_domain_conflict";
        for (first, second, constraint) in [
            (
                insert("one.test", "{}", 81, "http"),
                insert("one.test", "{}", 81, "http"),
                Some(domain),
            ),
            (
                insert("one.test", "{alias.test}", 81, "http"),
                insert("two.test", "{alias.test}", 81, "http"),
                Some(domain),
            ),
            (
                insert("*.example.test", "{}", 81, "http"),
                insert("sub.deep.example.test", "{}", 81, "http"),
                Some(domain),
            ),
            (
                insert("one.test", "{}", 81, "http"),
                insert("two.test", "{}", 81, "https"),
                Some("sites_ingress_protocol_conflict"),
            ),
            (
                legacy_insert("one.test"),
                legacy_insert("one.test"),
                Some(domain),
            ),
            (
                insert("one.test", "{}", 81, "http"),
                insert("one.test", "{}", 81, "http"),
                None,
            ),
        ] {
            race(&db, level, first, second, constraint).await;
        }
    }
    db.execute_unprepared("DELETE FROM sites WHERE ingress_port IS NOT NULL")
        .await
        .unwrap();
    db.execute_unprepared(&legacy_insert("app.test"))
        .await
        .unwrap();
    Migrator::down(&db, Some(1)).await.unwrap();
    assert!(scalar::<bool>(&db, "SELECT to_regclass('sites_domain_key') IS NOT NULL AND to_regclass('uq_sites_domain') IS NOT NULL").await);
    let error = db
        .execute_unprepared(&legacy_insert("app.test"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("duplicate key"));
    Migrator::up(&db, None).await.unwrap();
    assert_eq!(scalar::<i64>(&db, "SELECT count(*) FROM sites WHERE domain = 'app.test' AND ingress_port IS NULL").await, 1);
}
