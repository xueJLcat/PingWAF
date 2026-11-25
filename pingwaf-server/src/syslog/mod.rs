pub mod api;
pub mod config;
pub mod transport;
mod wire;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use config::Config;
use pingwaf_proto::control_plane::LogEntry;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend,
    QueryResult, Statement, TransactionTrait, Value,
};
use serde::Serialize;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use transport::{Connection, Material, Tls};
use uuid::Uuid;
pub(crate) use wire::Packet;

fn sql(s: &str, args: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, s, args)
}
struct Stored {
    revision: i64,
    config: Option<Config>,
    ca: String,
    cert: String,
    key: String,
}
async fn stored(db: &impl ConnectionTrait, lock: &str) -> Result<Stored> {
    let row = db
        .query_one(sql(
            &format!("SELECT * FROM syslog_settings WHERE id=1 {lock}"),
            vec![],
        ))
        .await?
        .context("syslog settings missing")?;
    let json: Option<serde_json::Value> = row.try_get("", "config")?;
    Ok(Stored {
        revision: row.try_get("", "revision")?,
        config: json.map(serde_json::from_value).transpose()?,
        ca: row.try_get("", "ca")?,
        cert: row.try_get("", "cert")?,
        key: row.try_get("", "sealed_key")?,
    })
}
impl Stored {
    fn material(&self, need_key: bool) -> Result<Material> {
        let key = if !need_key || self.key.is_empty() {
            String::new()
        } else {
            anyhow::ensure!(
                self.key.starts_with("enc:v1:"),
                "key: invalid stored key"
            );
            crate::notify::secretbox::open_string(&self.key)
                .context("key: instance encryption key unavailable")?
        };
        Ok(Material {
            ca: self.ca.clone(),
            cert: self.cert.clone(),
            key,
        })
    }
    fn active(&self) -> Result<Active> {
        let config = self.config.clone().unwrap_or_default();
        let tls = if config.enabled {
            config.validate(true)?;
            transport::tls(
                &config,
                &self.material(config.transport == "tls" && config.mtls)?,
            )?
        } else {
            None
        };
        Ok(Active {
            revision: self.revision,
            config,
            tls,
        })
    }
}
#[derive(Default)]
struct Active {
    revision: i64,
    config: Config,
    tls: Tls,
}
#[derive(Default, Serialize, Clone)]
struct Stats {
    access_written: u64,
    security_written: u64,
    filtered: u64,
    dropped_full: u64,
    dropped_size: u64,
    expired: u64,
    discarded: u64,
    storage_errors: u64,
    retries: u64,
    last_write: Option<DateTime<Utc>>,
    last_failure: Option<DateTime<Utc>>,
    error: Option<String>,
    peer: Option<String>,
}
type Queued = (Packet, OwnedSemaphorePermit);
pub struct Service {
    active: ArcSwap<Active>,
    tx: mpsc::Sender<Queued>,
    budget: Arc<Semaphore>,
    stats: Mutex<Stats>,
    started: DateTime<Utc>,
    last_test: Mutex<Option<Instant>>,
}
impl Service {
    pub async fn start(
        db: DatabaseConnection,
    ) -> (Arc<Self>, tokio::task::JoinSet<()>) {
        let (tx, rx) = mpsc::channel(1024);
        let service = Arc::new(Self {
            active: ArcSwap::from_pointee(Active::default()),
            tx,
            budget: Arc::new(Semaphore::new(4 * 1024 * 1024)),
            stats: Default::default(),
            started: Utc::now(),
            last_test: Default::default(),
        });
        if let Err(e) = service.refresh(&db).await {
            service.fail(&e);
        }
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(service.clone().persist(db.clone(), rx));
        workers.spawn(service.clone().dispatch(db));
        (service, workers)
    }
    fn fail(&self, e: &anyhow::Error) {
        let mut s = self.stats.lock().unwrap();
        s.last_failure = Some(Utc::now());
        s.error = Some(format!("{e:#}").chars().take(400).collect());
    }
    async fn refresh(&self, db: &DatabaseConnection) -> Result<()> {
        let row = db
            .query_one(sql(
                "SELECT revision FROM syslog_settings WHERE id=1",
                vec![],
            ))
            .await?
            .context("missing settings")?;
        let rev: i64 = row.try_get("", "revision")?;
        if rev != self.active.load().revision {
            let next = stored(db, "").await?.active()?;
            self.install(next);
        }
        Ok(())
    }
    fn install(&self, next: Active) {
        let next = Arc::new(next);
        let previous = self.active.rcu(|old| {
            if old.revision < next.revision {
                next.clone()
            } else {
                old.clone()
            }
        });
        if previous.revision < next.revision {
            let mut stats = self.stats.lock().unwrap();
            stats.error = None;
            stats.peer = None;
        }
    }
    pub(crate) fn project(
        &self,
        msg: &LogEntry,
        agent: Uuid,
        site: Option<Uuid>,
        time: DateTime<Utc>,
        security: bool,
    ) -> Option<Packet> {
        let active = self.active.load();
        let c = &active.config;
        if !c.enabled {
            return None;
        }
        let sev = c.severity.unwrap_or_else(|| wire::severity(msg, security));
        if (security && !c.security)
            || (!security && !c.access)
            || sev > c.threshold
            || c.sites
                .as_ref()
                .is_some_and(|ids| site.is_none_or(|id| !ids.contains(&id)))
        {
            self.stats.lock().unwrap().filtered += 1;
            return None;
        }
        let result = wire::encode(
            c,
            active.revision,
            msg,
            agent,
            site,
            time,
            if security { "security" } else { "access" },
            sev,
        );
        if result.is_none() {
            self.stats.lock().unwrap().dropped_size += 1
        }
        result
    }
    pub(crate) fn enqueue(&self, p: Packet) {
        if let Ok(permit) = self
            .budget
            .clone()
            .try_acquire_many_owned(p.bytes.len() as u32)
        {
            if self.tx.try_send((p, permit)).is_ok() {
                return;
            }
        }
        self.stats.lock().unwrap().dropped_full += 1;
    }
    async fn persist(
        self: Arc<Self>,
        db: DatabaseConnection,
        mut rx: mpsc::Receiver<Queued>,
    ) {
        let mut batch = Vec::with_capacity(64);
        while rx.recv_many(&mut batch, 64).await > 0 {
            let mut result = self.persist_batch(&db, &batch).await;
            if result.is_err() {
                tokio::time::sleep(Duration::from_millis(250)).await;
                result = self.persist_batch(&db, &batch).await;
            }
            if let Err(e) = result {
                self.fail(&e);
                self.stats.lock().unwrap().storage_errors += batch.len() as u64
            }
            batch.clear();
        }
    }
    async fn persist_batch(
        &self,
        db: &DatabaseConnection,
        batch: &[Queued],
    ) -> Result<()> {
        let tx = db.begin().await?;
        // Serialise admission and quota accounting, including other control-plane instances.
        tx.execute(sql("SELECT pg_advisory_xact_lock(74638501)", vec![]))
            .await?;
        let cfg=tx.query_one(sql("SELECT revision,COALESCE((config->>'enabled')::boolean,false) AS enabled,COALESCE((config->>'queue_mib')::bigint,0)*1048576 AS capacity FROM syslog_settings WHERE id=1 FOR SHARE",vec![])).await?.context("settings")?;
        let revision: i64 = cfg.try_get("", "revision")?;
        let enabled: bool = cfg.try_get("", "enabled")?;
        let capacity: i64 = cfg.try_get("", "capacity")?;
        let mut used = queue_stats(&tx).await?.1;
        let mut full = 0;
        let mut stale = 0;
        for (p, _) in batch {
            if !enabled || p.revision != revision {
                stale += 1;
                continue;
            }
            if used + p.bytes.len() as i64 > capacity {
                full += 1;
                continue;
            }
            tx.execute(sql("INSERT INTO syslog_queue(event_id,revision,kind,message) VALUES($1,$2,$3,$4) ON CONFLICT(event_id) DO NOTHING",
                vec![p.id.into(),p.revision.into(),p.kind.into(),p.bytes.clone().into()])).await?;
            used += p.bytes.len() as i64;
        }
        tx.commit().await?;
        let mut stats = self.stats.lock().unwrap();
        stats.dropped_full += full;
        stats.discarded += stale;
        Ok(())
    }
    async fn dispatch(self: Arc<Self>, db: DatabaseConnection) {
        let mut conn = None;
        let mut conn_rev = -1;
        let mut refresh = Instant::now();
        let mut expiry = Instant::now();
        loop {
            let result=async {
                if refresh.elapsed()>=Duration::from_secs(2){self.refresh(&db).await?;refresh=Instant::now();}
                let active=self.active.load_full();
                if active.revision!=conn_rev{conn=None;conn_rev=active.revision}
                if expiry.elapsed()>=Duration::from_secs(10){
                    let n=db.execute(sql("DELETE FROM syslog_queue WHERE created_at < now()-make_interval(hours=>$1)",vec![(active.config.retention_hours as i32).into()])).await?.rows_affected();
                    self.stats.lock().unwrap().expired+=n;expiry=Instant::now();
                }
                if !active.config.enabled{return Ok(false)}
                let tx=db.begin().await?;
                let lock=tx.query_one(sql("SELECT pg_try_advisory_xact_lock(74638502) AS acquired",vec![])).await?.context("lock")?;
                if !lock.try_get::<bool>("","acquired")?{return Ok(false)}
                // Hold a shared revision lock across the bounded socket write. A config
                // change cannot report success while an old-target send is still in flight.
                let version=tx.query_one(sql("SELECT revision FROM syslog_settings WHERE id=1 FOR SHARE",vec![])).await?.context("settings")?;
                if version.try_get::<i64>("","revision")?!=active.revision{return Ok(false)}
                let row=tx.query_one(sql("SELECT seq,kind,message,attempts,retry_at<=now() AS ready FROM syslog_queue ORDER BY seq LIMIT 1 FOR UPDATE",vec![])).await?;
                let Some(row)=row else{return Ok(false)};
                if !row.try_get::<bool>("","ready")?{return Ok(false)}
                self.send_row(tx,row,&active,&mut conn).await
            }.await;
            match result {
                Ok(true) => continue,
                Err(e) => self.fail(&e),
                _ => {},
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
    async fn send_row(
        &self,
        tx: DatabaseTransaction,
        row: QueryResult,
        a: &Active,
        conn: &mut Option<Connection>,
    ) -> Result<bool> {
        let seq: i64 = row.try_get("", "seq")?;
        let bytes: Vec<u8> = row.try_get("", "message")?;
        let c = &a.config;
        let result = async {
            if conn.is_none() {
                *conn = Some(Connection::connect(c, &a.tls).await?);
            }
            let socket = conn.as_mut().unwrap();
            socket.send(c, &bytes).await?;
            Ok(socket.peer())
        }
        .await;
        match result {
            Ok(peer) => {
                let kind: String = row.try_get("", "kind")?;
                tx.execute(sql(
                    "DELETE FROM syslog_queue WHERE seq=$1",
                    vec![seq.into()],
                ))
                .await?;
                tx.commit().await?;
                let mut s = self.stats.lock().unwrap();
                s.last_write = Some(Utc::now());
                s.error = None;
                s.peer = peer.map(|x| x.to_string());
                if kind == "access" {
                    s.access_written += 1
                } else {
                    s.security_written += 1
                }
                Ok(true)
            },
            Err(e) => {
                *conn = None;
                let attempts: i32 = row.try_get("", "attempts")?;
                let max = (c.retry_min * (1u64 << attempts.clamp(0, 16)))
                    .min(c.retry_max);
                let delay = rand::random_range(c.retry_min..=max) as i32;
                tx.execute(sql("UPDATE syslog_queue SET attempts=attempts+1,retry_at=now()+make_interval(secs=>$2::int) WHERE seq=$1",vec![seq.into(),delay.into()])).await?;
                tx.commit().await?;
                self.stats.lock().unwrap().retries += 1;
                self.fail(&e);
                Ok(false)
            },
        }
    }
}
async fn queue_stats(
    db: &impl ConnectionTrait,
) -> Result<(i64, i64, Option<DateTime<Utc>>)> {
    let r=db.query_one(sql("SELECT items AS n,bytes,(SELECT MIN(created_at) FROM syslog_queue) AS oldest FROM syslog_queue_usage WHERE id=1",vec![])).await?.context("queue stats")?;
    Ok((
        r.try_get("", "n")?,
        r.try_get("", "bytes")?,
        r.try_get("", "oldest")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm_migration::MigratorTrait;
    use tokio::net::UdpSocket;

    #[tokio::test]
    #[ignore = "requires an empty disposable PostgreSQL database"]
    async fn syslog_queue_postgres() -> Result<()> {
        let db = sea_orm::Database::connect(std::env::var(
            "PINGWAF_TEST_DATABASE_URL",
        )?)
        .await?;
        crate::migration::Migrator::up(&db, None).await?;
        let receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let config = Config {
            host: "127.0.0.1".into(),
            transport: "udp".into(),
            port: receiver.local_addr()?.port(),
            queue_mib: 1,
            enabled: true,
            access: true,
            ..Default::default()
        };
        db.execute(sql(
            "UPDATE syslog_settings SET revision=1,config=$1",
            vec![serde_json::to_value(&config)?.into()],
        ))
        .await?;
        let (svc, workers) = Service::start(db.clone()).await;
        drop(workers);
        let make = || {
            svc.project(
                &LogEntry::default(),
                Uuid::nil(),
                None,
                Utc::now(),
                false,
            )
            .unwrap()
        };
        let packet = make();
        let first = packet.id;
        let permit = || svc.budget.clone().try_acquire_owned().unwrap();
        svc.persist_batch(&db, &[(packet, permit())]).await?;
        let (n, bytes, _) = queue_stats(&db).await?;
        assert_eq!(n, 1);
        db.execute(sql("INSERT INTO syslog_queue(event_id,revision,kind,message) VALUES($1,1,'access',$2)",vec![Uuid::new_v4().into(),vec![0u8;(1048576-bytes) as usize].into()])).await?;
        svc.persist_batch(&db, &[(make(), permit())]).await?;
        assert_eq!(svc.stats.lock().unwrap().dropped_full, 1);
        assert_eq!(queue_stats(&db).await?.1, 1048576);
        db.execute(sql(
            "DELETE FROM syslog_queue WHERE event_id!=$1",
            vec![first.into()],
        ))
        .await?;
        db.execute(sql("UPDATE syslog_settings SET config=jsonb_set(config,'{enabled}','false'),revision=2",vec![])).await?;
        let (paused, paused_workers) = Service::start(db.clone()).await;
        assert!(paused
            .project(&LogEntry::default(), Uuid::nil(), None, Utc::now(), false)
            .is_none());
        assert_eq!(queue_stats(&db).await?.0, 1);
        drop(paused_workers);
        db.execute(sql("UPDATE syslog_settings SET config=jsonb_set(config,'{enabled}','true'),revision=3",vec![])).await?;
        let (_resumed, mut workers) = Service::start(db.clone()).await;
        let mut buf = [0u8; 8192];
        let n = tokio::time::timeout(
            Duration::from_secs(5),
            receiver.recv(&mut buf),
        )
        .await??;
        assert!(std::str::from_utf8(&buf[..n])?.contains(&first.to_string()));
        tokio::time::timeout(Duration::from_secs(5), async {
            while queue_stats(&db).await.unwrap().0 != 0 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?;
        workers.shutdown().await;
        crate::migration::Migrator::down(&db, Some(1)).await?;
        crate::migration::Migrator::up(&db, None).await?;
        assert_eq!(stored(&db, "").await?.revision, 0);
        assert_eq!(queue_stats(&db).await?.1, 0);
        Ok(())
    }
}
