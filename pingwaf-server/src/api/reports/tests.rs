use super::*;
use sea_orm_migration::MigratorTrait;

#[tokio::test]
#[ignore = "requires fresh disposable PostgreSQL"]
async fn fixed_report_postgres() {
    let db = sea_orm::Database::connect(
        std::env::var("PINGWAF_TEST_DATABASE_URL").unwrap(),
    )
    .await
    .unwrap();
    let empty=db.query_one_raw(Statement::from_string(DbBackend::Postgres,"SELECT to_regclass('sites') IS NULL AND to_regclass('seaql_migrations') IS NULL")).await.unwrap().unwrap();
    assert!(empty.try_get_by_index::<bool>(0).unwrap());
    crate::migration::Migrator::up(&db, None).await.unwrap();
    let user = AuthUser::new(Uuid::new_v4(), "stats@example.test", "admin");
    let site = Uuid::new_v4();
    let idle = Uuid::new_v4();
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO users(id,email,password_hash,created_at,updated_at) VALUES($1,$2,'unused',now(),now())",[user.id.into(),user.email.clone().into()])).await.unwrap();
    for (id, name) in
        [(site, "active.example.test"), (idle, "idle.example.test")]
    {
        db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,"INSERT INTO sites(id,user_id,name,domain,created_at,updated_at) VALUES($1,$2,$3,$3,now(),now())",
            [id.into(),user.id.into(),name.into()])).await.unwrap();
    }
    let from = Utc::now()
        .date_naive()
        .pred_opt()
        .unwrap()
        .and_hms_opt(15, 58, 0)
        .unwrap()
        .and_utc();
    let to = from + chrono::Duration::minutes(4);
    let selection = Selection {
        sites: vec![site, idle],
        from,
        to,
        timezone: "Asia/Shanghai".into(),
    };
    for id in [site, idle] {
        db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO report_coverage SELECT t,$1,15 FROM generate_series($2::timestamptz,$3::timestamptz-interval '1 minute',interval '1 minute') t",
            [id.into(),from.into(),to.into()])).await.unwrap();
    }
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO access_logs(site_id,timestamp,client_ip,method) SELECT $1,$2,'127.0.0.1','GET' FROM generate_series(1,3)",
        [site.into(),from.into()])).await.unwrap();
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO security_events(site_id,timestamp,client_ip,method,action,event_type,created_at) SELECT $1,$2,'127.0.0.1','GET',kind,'managed',now() FROM unnest(ARRAY['block','block','challenge']) kind",
        [site.into(),from.into()])).await.unwrap();
    let state = State(AppState::new(
        db.clone(),
        Default::default(),
        crate::grpc::AgentRegistry::new(),
    ));
    let outsider =
        AuthUser::new(Uuid::new_v4(), "viewer@example.test", "viewer");
    assert!(
        create(state.clone(), outsider.clone(), Json(selection.clone()))
            .await
            .is_err()
    );
    let snap = snapshot::collect(&db, &user, selection.clone(), false)
        .await
        .unwrap();
    assert_eq!(snap.categories, vec![("managed".to_owned(), 3)]);
    assert!(snap.metrics.iter().all(|r| r.covered));
    let active = snap.metrics.iter().find(|r| r.requests == Some(3)).unwrap();
    assert_eq!((active.blocked, active.challenged), (Some(2), Some(1)));
    assert!(snap
        .metrics
        .iter()
        .filter(|r| r.site == idle)
        .all(|r| r.requests == Some(0)));
    assert!(snap.metrics.iter().any(|r| r.local_time.ends_with("00:00")));
    let id = create(state.clone(), user.clone(), Json(selection.clone()))
        .await
        .unwrap()
        .0;
    let queued = list(state.clone(), user.clone()).await.unwrap().0;
    assert_eq!(queued[0]["timezone"], selection.timezone);
    assert_eq!(queued[0]["from"], json!(selection.from));
    assert_eq!(queued[0]["to"], json!(selection.to));
    worker::run(&db).await.unwrap();
    async fn bytes(r: Response) -> Vec<u8> {
        axum::body::to_bytes(r.into_body(), 12 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec()
    }
    let pdf = bytes(
        download(state.clone(), user.clone(), Path((id, "pdf".into())))
            .await
            .unwrap(),
    )
    .await;
    let csv = bytes(
        download(state.clone(), user.clone(), Path((id, "csv".into())))
            .await
            .unwrap(),
    )
    .await;
    assert!(pdf.starts_with(b"%PDF"));
    assert!(csv.starts_with(&[0xef, 0xbb, 0xbf]));
    let text = std::str::from_utf8(&csv).unwrap();
    assert!(text.contains("\"请求量\",\"3\""));
    assert!(text.contains("\"挑战量\",\"1\""));
    assert!(text.contains("\"拦截量\",\"2\""));
    if let Ok(file) = std::env::var("PINGWAF_TEST_REPORT_PDF") {
        std::fs::write(file, &pdf).unwrap();
    }
    db.execute_unprepared(
        "DELETE FROM report_coverage; DELETE FROM access_logs",
    )
    .await
    .unwrap();
    assert_eq!(
        csv,
        bytes(
            download(state.clone(), user.clone(), Path((id, "csv".into())))
                .await
                .unwrap()
        )
        .await
    );
    assert!(download(state.clone(), outsider.clone(), Path((id, "pdf".into())))
        .await
        .is_err());
    assert!(remove(state.clone(), outsider, Path(id)).await.is_err());
    let other_owner = AuthUser::new(Uuid::new_v4(), "other@example.test", "admin");
    assert!(remove(state.clone(), other_owner, Path(id)).await.is_err());
    assert_eq!(remove(state.clone(), user.clone(), Path(id)).await.unwrap(), StatusCode::NO_CONTENT);
    assert!(download(state.clone(), user.clone(), Path((id, "csv".into()))).await.is_err());
    assert!(remove(state.clone(), user.clone(), Path(id)).await.is_err());
    let gap = snapshot::collect(&db, &user, selection, true)
        .await
        .unwrap();
    assert!(gap
        .metrics
        .iter()
        .all(|r| !r.covered && r.requests.is_none()));

    // The default static-access-log filter does not stop the security-event
    // collector, or the collection of requests that are actually logged.
    db.execute_unprepared("UPDATE log_retention_settings SET skip_static_access_logs=true").await.unwrap();
    let key = Uuid::new_v4();
    let node = Uuid::new_v4();
    let foreign_owner = Uuid::new_v4();
    let foreign_site = Uuid::new_v4();
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO users(id,email,password_hash,created_at,updated_at) VALUES($1,'foreign@example.test','unused',now(),now())",
        [foreign_owner.into()])).await.unwrap();
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO sites(id,user_id,name,domain,created_at,updated_at) VALUES($1,$2,'foreign','foreign.example.test',now(),now())",
        [foreign_site.into(), foreign_owner.into()])).await.unwrap();
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO api_keys(id,user_id,name,key_hash,key_prefix,created_at) VALUES($1,$2,'coverage','unused','test',now())",
        [key.into(), user.id.into()])).await.unwrap();
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO agents(id,api_key_id,hostname,ip_address,status,site_scope,last_heartbeat,registered_at)
         VALUES($1,$2,'coverage','127.0.0.1','online','all',now(),now())",
        [node.into(), key.into()])).await.unwrap();
    worker::coverage(&db).await.unwrap();
    assert!(db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT 1 FROM report_coverage WHERE site_id=$1", [foreign_site.into()])).await.unwrap().is_none());
    let row = db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT minute FROM report_coverage WHERE site_id=$1 ORDER BY minute DESC LIMIT 1",
        [idle.into()])).await.unwrap().unwrap();
    let minute: DateTime<Utc> = row.try_get("", "minute").unwrap();
    let window = Selection { sites: vec![idle], timezone: "UTC".into(), from: minute-chrono::Duration::minutes(1), to: Utc::now() };
    let live = snapshot::collect(&db, &user, window.clone(), true).await.unwrap();
    assert_eq!(live.nodes.len(), 1);
    assert!(live.nodes[0].online);
    assert!(live.metrics.iter().any(|r| r.requests==Some(0) && r.blocked==Some(0) && r.challenged==Some(0)));
    assert!(live.metrics.iter().any(|r| r.requests.is_none() && !r.covered));
    db.execute_unprepared("DELETE FROM report_coverage; UPDATE agents SET last_heartbeat=now()-interval '10 minutes'").await.unwrap();
    worker::coverage(&db).await.unwrap();
    let offline = snapshot::collect(&db, &user, window, true).await.unwrap();
    assert!(!offline.nodes[0].online);
    assert!(offline.metrics.iter().all(|r| !r.covered && r.requests.is_none() && r.blocked.is_none()));
}
