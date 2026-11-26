use super::*;
use pingwaf_proto::{
    PageIntegrityObservation, PageIntegrityRule, PageIntegrityRules,
};

async fn scoped_transaction(
    db: &DatabaseConnection,
    agent: Uuid,
    session: Uuid,
    site: Uuid,
) -> Result<DatabaseTransaction, BuildError> {
    let tx = db
        .begin_with_config(Some(IsolationLevel::RepeatableRead), None)
        .await?;
    require_session(&tx, agent, session).await?;
    let (_, owner) = authorize(&tx, agent).await?;
    if tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT 1 FROM sites s JOIN panel_site_listeners a ON a.site_id=s.id WHERE s.id=$1 AND a.agent_id=$2 AND s.user_id=$3 AND s.status='active'",
        [site.into(),agent.into(),owner.into()])).await?.is_none() { return Err(BuildError::Forbidden); }
    Ok(tx)
}

pub(in crate::grpc) async fn page_rules(
    tx: &DatabaseTransaction,
    site: Uuid,
    rule: Option<Uuid>,
) -> Result<Vec<PageIntegrityRule>, DbErr> {
    let rows=tx.query_all(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT r.id,r.path,r.mode,r.dynamic_stage,r.dynamic_region,r.dynamic_test_digest,v.version,v.digest,v.content_type,
             CASE WHEN $2::uuid IS NOT NULL THEN v.body END AS body
             FROM page_integrity_rules r LEFT JOIN page_integrity_versions v ON (v.rule_id,v.version)=(r.id,r.active_version)
             WHERE site_id=$1 AND ($2::uuid IS NULL OR r.id=$2) ORDER BY path", [site.into(),rule.into()])).await?;
    let mut rules = Vec::with_capacity(rows.len());
    for row in rows {
        rules.push(PageIntegrityRule {
            id: row.try_get::<Uuid>("", "id")?.to_string(),
            path: row.try_get("", "path")?,
            mode: row.try_get("", "mode")?,
            dynamic_stage: row.try_get("", "dynamic_stage")?,
            dynamic_region: row.try_get("", "dynamic_region")?,
            dynamic_test_digest: row.try_get("", "dynamic_test_digest")?,
            version: row
                .try_get::<Option<i64>>("", "version")?
                .unwrap_or_default(),
            digest: row
                .try_get::<Option<String>>("", "digest")?
                .unwrap_or_default(),
            content_type: row
                .try_get::<Option<String>>("", "content_type")?
                .unwrap_or_default(),
            approved: row
                .try_get::<Option<Vec<u8>>>("", "body")?
                .unwrap_or_default(),
        });
    }
    Ok(rules)
}

pub(in crate::grpc) async fn read_pages(
    db: &DatabaseConnection,
    agent: Uuid,
    session: Uuid,
    site: Uuid,
    rule: Option<Uuid>,
) -> Result<PageIntegrityRules, Status> {
    let read = async {
        let tx = scoped_transaction(db, agent, session, site).await?;
        let rules = page_rules(&tx, site, rule).await?;
        tx.commit().await?;
        Ok(PageIntegrityRules { rules })
    }
    .await;
    status_for_scope(agent, read)
}

pub(in crate::grpc) async fn observe_page(
    db: &DatabaseConnection,
    agent: Uuid,
    session: Uuid,
    site: Uuid,
    rule: Uuid,
    event: PageIntegrityObservation,
) -> Result<(), Status> {
    use pingwaf_content::protection::{MAX_PAGE_BYTES, body_digest};
    if !matches!(
        event.category.as_str(),
        "capture"
            | "changed"
            | "unavailable"
            | "skipped"
            | "detection_failed"
            | "copy_corrupt"
    ) || event.detail.len() > 128
        || event.content_type.len() > 256
        || event.count == 0
        || event.count > 65535
    {
        return Err(Status::invalid_argument("invalid observation"));
    }
    if let Some(body) = &event.candidate {
        if body.len() > MAX_PAGE_BYTES
            || !matches!(event.category.as_str(), "capture" | "changed")
            || body_digest(body) != event.detail
            || event.content_type.is_empty()
            || !event.content_type.bytes().all(|b| (32..=126).contains(&b))
        {
            return Err(Status::invalid_argument("invalid candidate"));
        }
    }
    let alert = match event.category.as_str() {
        "changed" | "unavailable" | "detection_failed" | "copy_corrupt" => {
            Some(crate::notify::AlertEvent {
                event_type: crate::models::event_type::PAGE_INTEGRITY.into(),
                severity: crate::models::severity::WARNING,
                title: format!("Public page integrity: {}", event.category),
                message: format!("Site {site}, rule {rule}: {}", event.detail),
                details: Some(
                    serde_json::json!({"site_id":site,"rule_id":rule,"category":event.category,"detail":event.detail}),
                ),
                dedup_key: Some(format!(
                    "{site}:{rule}:{}:{}",
                    event.category, event.detail
                )),
            })
        },
        _ => None,
    };
    let write=async {
        let tx=scoped_transaction(db,agent,session,site).await?;
        tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT 1 FROM page_integrity_rules WHERE id=$1 AND site_id=$2 FOR UPDATE",[rule.into(),site.into()])).await?.ok_or(BuildError::Forbidden)?;
        if let Some(bytes)=event.candidate {
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE page_integrity_rules SET candidate_digest=$2,candidate_body=$3,candidate_type=$4,candidate_at=now() WHERE id=$1
                 AND (candidate_digest,candidate_type) IS DISTINCT FROM ($2,$4)",
                [rule.into(),event.detail.clone().into(),bytes.into(),event.content_type.into()])).await?;
        }
        if event.category!="capture" {
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "INSERT INTO page_integrity_events(rule_id,category,detail,observations) VALUES($1,$2,$3,$4)
                 ON CONFLICT(rule_id,category,detail) DO UPDATE SET last_seen=now(),observations=page_integrity_events.observations+excluded.observations",
                [rule.into(),event.category.clone().into(),event.detail.clone().into(),(event.count as i64).into()])).await?;
        }
        let notify = if alert.is_some() {
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE page_integrity_events SET last_notified=now() WHERE rule_id=$1 AND category=$2 AND detail=$3
                 AND (last_notified IS NULL OR last_notified < now()-interval '10 minutes')",
                [rule.into(),event.category.into(),event.detail.into()])).await?.rows_affected()==1
        } else {false};
        tx.commit().await?;
        Ok(notify)
    }.await;
    let notify = status_for_scope(agent, write)?;
    if let Some(alert) = alert.filter(|_| notify) {
        crate::notify::emit(alert).await;
    }
    Ok(())
}
