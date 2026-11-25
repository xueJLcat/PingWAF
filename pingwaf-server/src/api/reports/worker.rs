use super::*;
use sea_orm::{DatabaseConnection, DbErr};

pub(crate) fn start(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(Duration::from_secs(15));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut task: Option<tokio::task::JoinHandle<()>> = None;
        loop {
            ticks.tick().await;
            if let Err(e) = coverage(&state.db).await {
                tracing::warn!(error=%e,"report coverage sampling failed");
            }
            if task.as_ref().is_some_and(|t| !t.is_finished()) {
                continue;
            }
            let db = state.db.clone();
            task = Some(tokio::spawn(async move {
                if let Err(e) = run(&db).await {
                    tracing::warn!(error=%e,"report worker failed");
                }
            }));
        }
    })
}

pub(super) async fn coverage(db: &DatabaseConnection) -> Result<(), DbErr> {
    db.execute_unprepared("
      INSERT INTO report_coverage(minute,site_id,samples)
      SELECT date_trunc('minute',now()),l.site_id,1 << (floor(extract(second FROM now()))::int/15)
      FROM panel_site_listeners l JOIN agents a ON a.id=l.agent_id
      WHERE l.status='active'
      GROUP BY l.site_id HAVING bool_and(a.status='online' AND coalesce(a.last_heartbeat>now()-interval '30 seconds',false))
      ON CONFLICT(site_id,minute) DO UPDATE SET samples=report_coverage.samples | excluded.samples
    ").await?;
    Ok(())
}

pub(super) async fn run(db: &DatabaseConnection) -> Result<(), DbErr> {
    let tx = db.begin().await?;
    tx.execute_unprepared("SELECT pg_advisory_xact_lock(74511631)")
        .await?;
    tx.execute_unprepared("DELETE FROM protection_reports WHERE expires_at<=now(); DELETE FROM report_coverage WHERE minute<now()-interval '8 days'").await?;
    let lease = Uuid::new_v4();
    let row=tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,"
      UPDATE protection_reports SET status='running',lease=$1,lease_until=now()+interval '5 minutes'
      WHERE id=(SELECT id FROM protection_reports WHERE (status='queued' OR (status='running' AND lease_until<=now()))
                 AND NOT EXISTS(SELECT 1 FROM protection_reports WHERE status='running' AND lease_until>now())
                 ORDER BY created_at,id LIMIT 1) RETURNING id,owner_id,selection,snapshot",[lease.into()])).await?;
    tx.commit().await?;
    let Some(row) = row else { return Ok(()) };
    let id: Uuid = row.try_get("", "id")?;
    let owner: Uuid = row.try_get("", "owner_id")?;
    let selection: Value = row.try_get("", "selection")?;
    let saved: Option<Value> = row.try_get("", "snapshot")?;
    let outcome=async {
        let selection:Selection=serde_json::from_value(selection).map_err(|_|ApiError::Internal("invalid report selection".into()))?;
        let user=db.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT email,role FROM users WHERE id=$1 AND NOT disabled",[owner.into()])).await?.ok_or_else(||ApiError::Forbidden("report owner unavailable".into()))?;
        let user=AuthUser::new(owner,user.try_get::<String>("","email")?,user.try_get::<String>("","role")?);
        let snap:Snapshot=if let Some(saved)=saved {
            let tx=db.begin().await?;snapshot::scope(&tx,&user,&selection).await?;tx.commit().await?;
            serde_json::from_value(saved).map_err(|_|ApiError::Internal("invalid report snapshot".into()))?
        }else{
            let snap=snapshot::collect(db,&user,selection,false).await?;
            db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE protection_reports SET snapshot=$3 WHERE id=$1 AND lease=$2",[id.into(),lease.into(),json!(snap).into()])).await?;
            snap
        };
        tokio::task::spawn_blocking(move ||export::render(&snap)).await.map_err(|_|ApiError::Internal("report renderer interrupted".into()))?
    }.await;
    match outcome {
        Ok((pdf, csv)) => {
            db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE protection_reports SET pdf=$3,csv=$4,status='ready',lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2",
            [id.into(),lease.into(),pdf.into(),csv.into()])).await?;
        },
        Err(error) => {
            tracing::warn!(%id,?error,"report generation failed");
            db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE protection_reports SET status='failed',error='Report generation failed; check scope, data and server logs',lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2",
            [id.into(),lease.into()])).await?;
        },
    }
    Ok(())
}
