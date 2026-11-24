use anyhow::Context;
use pingwaf_content::protection::{Approved, Observation, Policy, Rule};
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

pub(super) async fn prepare(
    site: Uuid,
    rules: &[pingwaf_proto::PageIntegrityRule],
) -> anyhow::Result<Arc<Policy>> {
    let agent = pingwaf_agent::agent_instance().context("node unavailable")?;
    let mut paths = HashMap::new();
    for rule in rules {
        let approved = if rule.version > 0 {
            let bytes = agent.client.approved_page(site, rule).await?;
            Some(Approved {
                digest: rule.digest.clone(),
                media_type: rule.content_type.clone(),
                body: bytes.into(),
            })
        } else {
            None
        };
        paths.insert(
            rule.path.clone(),
            Rule {
                id: rule.id.clone(),
                trusted_copy: rule.mode == "trusted_copy",
                dynamic_stage: rule.dynamic_stage.clone(),
                dynamic_region: rule.dynamic_region.clone(),
                dynamic_test_digest: rule.dynamic_test_digest.clone(),
                approved,
            },
        );
    }
    // Count identical observations before the asynchronous control-plane write.
    // Bound distinct keys and retained bodies even if the control plane stalls.
    let pending =
        Arc::new(std::sync::Mutex::new(Vec::<(Observation, u32)>::new()));
    let queue = pending.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let batch = std::mem::take(
                &mut *queue.lock().unwrap_or_else(|e| e.into_inner()),
            );
            for (event, count) in batch {
                if let Err(error) =
                    agent.client.report_page(site, event, count).await
                {
                    tracing::warn!(%site,%error,"could not report public page observation");
                }
            }
        }
    });
    Ok(Arc::new(Policy {
        paths,
        report: Box::new(move |event| {
            let mut queue = pending.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(index) = queue.iter().position(|(old, _)| {
                old.rule == event.rule
                    && old.category == event.category
                    && old.detail == event.detail
                    && old.media_type == event.media_type
            }) {
                let (_, count) = queue.remove(index);
                queue.push((event, count.saturating_add(1).min(65535)));
            } else if queue.len() < 8 {
                queue.push((event, 1));
            } else {
                tracing::debug!(%site,"page observation queue full");
                return;
            }
            let _ = tx.try_send(());
        }),
    }))
}
