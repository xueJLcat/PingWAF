use super::super::{common, error::ApiError};
use super::{MetricRow, Node, Selection, Snapshot};
use crate::auth::AuthUser;
use chrono::{DateTime, Utc};
use sea_orm::{
    AccessMode, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    DbBackend, IsolationLevel, Statement, TransactionTrait,
};
use uuid::Uuid;

pub(super) async fn scope(
    tx: &DatabaseTransaction,
    user: &AuthUser,
    selection: &Selection,
) -> Result<(), ApiError> {
    if selection.sites.is_empty()
        || selection.sites.len() > 16
        || selection.to <= selection.from
        || selection.to - selection.from > chrono::Duration::days(7)
        || selection.to > Utc::now() + chrono::Duration::seconds(30)
        || selection.timezone.len() > 80
    {
        return Err(ApiError::BadRequest(
            "select 1–16 sites and a past interval of up to seven days".into(),
        ));
    }
    for id in &selection.sites {
        common::load_site(tx, *id, user, false).await?;
    }
    if tx
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT 1 FROM pg_timezone_names WHERE name=$1",
            [selection.timezone.clone().into()],
        ))
        .await?
        .is_none()
    {
        return Err(ApiError::BadRequest("unknown timezone".into()));
    }
    Ok(())
}

pub(super) async fn collect(
    db: &DatabaseConnection,
    user: &AuthUser,
    selection: Selection,
    live: bool,
) -> Result<Snapshot, ApiError> {
    let tx = db
        .begin_with_config(
            Some(IsolationLevel::RepeatableRead),
            Some(AccessMode::ReadOnly),
        )
        .await?;
    tx.execute_unprepared("SET LOCAL statement_timeout = '15s'")
        .await?;
    scope(&tx, user, &selection).await?;
    let ids = serde_json::to_value(&selection.sites).unwrap();
    let seconds: i32 = if live {
        60
    } else if selection.to - selection.from <= chrono::Duration::hours(12) {
        900
    } else {
        3600
    };
    let rows=tx.query_all(Statement::from_sql_and_values(DbBackend::Postgres,"
      WITH chosen AS (SELECT id,domain FROM sites WHERE id IN (SELECT jsonb_array_elements_text($1)::uuid)),
      params AS (SELECT make_interval(secs=>$5) AS step),
      buckets AS (SELECT generate_series(date_bin(step,$2::timestamptz,'2000-01-01'::timestamptz),$3::timestamptz-interval '1 microsecond',step) AS t FROM params),
      access AS (SELECT site_id,date_bin(step,timestamp,'2000-01-01'::timestamptz) AS t,count(*) AS n
        FROM access_logs JOIN chosen ON chosen.id=site_id CROSS JOIN params WHERE timestamp >= $2 AND timestamp < $3 GROUP BY 1,2),
      events AS (SELECT site_id,date_bin(step,timestamp,'2000-01-01'::timestamptz) AS t,
        count(*) FILTER(WHERE action='block') AS blocked,count(*) FILTER(WHERE action='challenge') AS challenged
        FROM security_events JOIN chosen ON chosen.id=site_id CROSS JOIN params WHERE timestamp >= $2 AND timestamp < $3 GROUP BY 1,2),
      covered AS (SELECT site_id,date_bin(step,minute,'2000-01-01'::timestamptz) AS t,count(*) FILTER(WHERE samples=15) AS n
        FROM report_coverage JOIN chosen ON chosen.id=site_id CROSS JOIN params WHERE minute>=date_trunc('minute',$2::timestamptz) AND minute<$3 GROUP BY 1,2)
      SELECT c.id,c.domain,b.t,to_char(timezone($4,b.t),'YYYY-MM-DD HH24:MI') AS local_time,
        coalesce(a.n,0) AS requests,coalesce(e.blocked,0) AS blocked,coalesce(e.challenged,0) AS challenged,
        coalesce(cv.n,0)>=ceil(extract(epoch FROM least(b.t+p.step,$3)-date_trunc('minute',greatest(b.t,$2)))/60) AS covered
      FROM chosen c CROSS JOIN buckets b CROSS JOIN params p LEFT JOIN access a ON (a.site_id,a.t)=(c.id,b.t)
      LEFT JOIN events e ON (e.site_id,e.t)=(c.id,b.t) LEFT JOIN covered cv ON (cv.site_id,cv.t)=(c.id,b.t) ORDER BY b.t,c.domain,c.id",
      [ids.clone().into(),selection.from.into(),selection.to.into(),selection.timezone.clone().into(),(seconds as f64).into()])).await?;
    let mut metrics = Vec::with_capacity(rows.len());
    for row in rows {
        let covered: bool = row.try_get("", "covered")?;
        let metric = |value: i64| {
            if covered || value > 0 {
                Some(value)
            } else {
                None
            }
        };
        metrics.push(MetricRow {
            site: row.try_get("", "id")?,
            domain: row.try_get("", "domain")?,
            bucket: row.try_get("", "t")?,
            local_time: row.try_get("", "local_time")?,
            requests: metric(row.try_get("", "requests")?),
            blocked: metric(row.try_get("", "blocked")?),
            challenged: metric(row.try_get("", "challenged")?),
            covered,
        });
    }
    let rows=tx.query_all(Statement::from_sql_and_values(DbBackend::Postgres,"
      SELECT coalesce(event_type,'unknown') AS category,count(*) AS n FROM security_events WHERE site_id IN
      (SELECT jsonb_array_elements_text($1)::uuid) AND timestamp>=$2 AND timestamp<$3 GROUP BY 1 ORDER BY 2 DESC,1 LIMIT 64",
      [ids.clone().into(),selection.from.into(),selection.to.into()])).await?;
    let mut categories = Vec::new();
    for row in rows {
        categories.push((row.try_get("", "category")?, row.try_get("", "n")?));
    }
    let rows=tx.query_all(Statement::from_sql_and_values(DbBackend::Postgres,"
      SELECT DISTINCT a.id,coalesce(a.display_name,a.hostname) AS name, a.last_heartbeat,
      (a.status='online' AND coalesce(a.last_heartbeat>now()-interval '90 seconds',false)) AS online
      FROM agents a JOIN agent_sites s ON s.agent_id=a.id WHERE s.site_id IN (SELECT jsonb_array_elements_text($1)::uuid) ORDER BY name,id",
      [ids.into()])).await?;
    let mut nodes = Vec::new();
    for row in rows {
        nodes.push(Node {
            id: row.try_get::<Uuid>("", "id")?,
            name: row.try_get("", "name")?,
            heartbeat: row
                .try_get::<Option<DateTime<Utc>>>("", "last_heartbeat")?,
            online: row.try_get("", "online")?,
        });
    }
    tx.commit().await?;
    Ok(Snapshot {
        selection,
        generated_at: Utc::now(),
        metrics,
        categories,
        nodes,
    })
}
