//! The AI API's rate limiter: ace3's `aceapi_ai/ratelimit.py`, on Postgres where ace3 uses Redis.
//!
//! Three controls for each bucket (a backend's name, `search` or `export`), the same for every node
//! since the counts are rows every node reads (migration 0062):
//!
//! - **Concurrency.** A slot is a row of `ai.inflight`. Taking one first removes the bucket's rows
//!   older than its longest query and a grace, which a process that died left behind, then counts
//!   what is left against the limit and adds its own, all under the bucket's advisory lock, so two
//!   requests can't both take the last slot. Giving it back removes the row; the removal of old rows
//!   is the second net.
//! - **Requests a minute**, a fixed window: a row of `ai.windows` counted up.
//! - **Requests an hour**, the same: the control that protects a data source's quota when it is
//!   shared with production analysis.
//!
//! Both windows are counted before either is checked, as in ace3, so a request the minute refuses
//! still counts against the hour.
//!
//! [`AiLimiter`] is what the service asks, so a test can put a limiter in that refuses or can't be
//! reached. When the database can't be reached the answer is `Unavailable`, and the service refuses
//! the request unless the site chose to fail open: a control that goes away when its store blips
//! isn't one.

use ace_core::Db;
use chrono::{DateTime, TimeDelta, Utc};
use uuid::Uuid;

use super::{AiFuture, AiLimits};

/// What a slot's age may pass its bucket's longest query by before it is taken for dead: time to
/// write the answer after the query ends. ace3's `STALE_SLOT_GRACE_SECONDS`.
pub const STALE_SLOT_GRACE_SECONDS: i64 = 60;

/// Which limit refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    Concurrency,
    Rate,
    Budget,
}

impl LimitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LimitKind::Concurrency => "concurrency",
            LimitKind::Rate => "rate",
            LimitKind::Budget => "budget",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitError {
    /// A limit refused the request: ace3's `RateLimitExceeded`.
    Exceeded {
        kind: LimitKind,
        detail: String,
        retry_after_seconds: u64,
    },
    /// The limiter's store couldn't be reached: ace3's `RateLimitUnavailable`. The text is for the
    /// log.
    Unavailable(String),
}

/// A held concurrency slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub bucket: String,
    pub token: Uuid,
}

/// What the service asks of a limiter.
pub trait AiLimiter: std::fmt::Debug + Send + Sync {
    /// Takes one of the bucket's concurrency slots.
    fn acquire<'a>(
        &'a self,
        bucket: &'a str,
        limits: &'a AiLimits,
    ) -> AiFuture<'a, Result<Slot, LimitError>>;

    /// Counts a request against the bucket's minute and hour, and refuses it if either is used up.
    fn check_request<'a>(
        &'a self,
        bucket: &'a str,
        limits: &'a AiLimits,
    ) -> AiFuture<'a, Result<(), LimitError>>;

    /// Gives a slot back. A failure is logged: the next request for the bucket reaps the slot once
    /// it is stale.
    fn release(&self, slot: Slot) -> AiFuture<'_, ()>;
}

/// The limiter on Postgres.
#[derive(Debug, Clone)]
pub struct PgLimiter {
    db: Db,
}

fn unavailable(error: impl std::fmt::Display) -> LimitError {
    LimitError::Unavailable(error.to_string())
}

impl PgLimiter {
    pub fn new(db: Db) -> Self {
        PgLimiter { db }
    }

    /// `acquire` at a given time, which a slot's row records.
    pub async fn acquire_at(
        &self,
        bucket: &str,
        limits: &AiLimits,
        now: DateTime<Utc>,
    ) -> Result<Slot, LimitError> {
        let stale = now
            - TimeDelta::seconds(i64::from(limits.max_query_timeout) + STALE_SLOT_GRACE_SECONDS);
        let token = Uuid::new_v4();
        let mut tx = self.db.begin().await.map_err(unavailable)?;
        // one request at a time for a bucket, so the count and the insert are one step
        sqlx::query!(
            "SELECT pg_advisory_xact_lock(hashtextextended('ai.inflight:' || $1, 0))",
            bucket,
        )
        .execute(tx.conn())
        .await
        .map_err(unavailable)?;
        sqlx::query!(
            "DELETE FROM ai.inflight WHERE bucket = $1 AND started_at <= $2",
            bucket,
            stale,
        )
        .execute(tx.conn())
        .await
        .map_err(unavailable)?;
        let held = sqlx::query_scalar!(
            r#"SELECT count(*) AS "held!" FROM ai.inflight WHERE bucket = $1"#,
            bucket,
        )
        .fetch_one(tx.conn())
        .await
        .map_err(unavailable)?;
        let refused = held >= i64::from(limits.max_concurrency);
        if !refused {
            sqlx::query!(
                "INSERT INTO ai.inflight (token, bucket, started_at) VALUES ($1, $2, $3)",
                token,
                bucket,
                now,
            )
            .execute(tx.conn())
            .await
            .map_err(unavailable)?;
        }
        // committed either way: what was reaped stays reaped
        tx.commit().await.map_err(unavailable)?;
        if refused {
            return Err(LimitError::Exceeded {
                kind: LimitKind::Concurrency,
                detail: format!(
                    "backend {bucket} allows {} concurrent queries",
                    limits.max_concurrency
                ),
                retry_after_seconds: 10,
            });
        }
        Ok(Slot {
            bucket: bucket.to_owned(),
            token,
        })
    }

    /// `check_request` at a given time.
    pub async fn check_request_at(
        &self,
        bucket: &str,
        limits: &AiLimits,
        now: DateTime<Utc>,
    ) -> Result<(), LimitError> {
        let seconds = now.timestamp();
        let (minute, hour) = (seconds.div_euclid(60), seconds.div_euclid(3600));
        let mut tx = self.db.begin().await.map_err(unavailable)?;
        let mut counts = [0i32; 2];
        for (count, (kind, window)) in counts.iter_mut().zip([("minute", minute), ("hour", hour)]) {
            *count = sqlx::query_scalar!(
                "INSERT INTO ai.windows (bucket, kind, window_start, count) VALUES ($1, $2, $3, 1)
                 ON CONFLICT (bucket, kind, window_start)
                 DO UPDATE SET count = ai.windows.count + 1
                 RETURNING count",
                bucket,
                kind,
                window,
            )
            .fetch_one(tx.conn())
            .await
            .map_err(unavailable)?;
        }
        sqlx::query!(
            "DELETE FROM ai.windows
             WHERE bucket = $1
               AND ((kind = 'minute' AND window_start < $2) OR (kind = 'hour' AND window_start < $3))",
            bucket,
            minute - 2,
            hour - 2,
        )
        .execute(tx.conn())
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;

        let wait = |window: i64| u64::try_from(window - seconds.rem_euclid(window)).unwrap_or(1);
        if i64::from(counts[0]) > i64::from(limits.requests_per_minute) {
            return Err(LimitError::Exceeded {
                kind: LimitKind::Rate,
                detail: format!(
                    "backend {bucket} allows {} requests per minute",
                    limits.requests_per_minute
                ),
                retry_after_seconds: wait(60),
            });
        }
        if i64::from(counts[1]) > i64::from(limits.hourly_budget) {
            return Err(LimitError::Exceeded {
                kind: LimitKind::Budget,
                detail: format!(
                    "backend {bucket} allows {} requests per hour",
                    limits.hourly_budget
                ),
                retry_after_seconds: wait(3600),
            });
        }
        Ok(())
    }
}

impl AiLimiter for PgLimiter {
    fn acquire<'a>(
        &'a self,
        bucket: &'a str,
        limits: &'a AiLimits,
    ) -> AiFuture<'a, Result<Slot, LimitError>> {
        Box::pin(self.acquire_at(bucket, limits, Utc::now()))
    }

    fn check_request<'a>(
        &'a self,
        bucket: &'a str,
        limits: &'a AiLimits,
    ) -> AiFuture<'a, Result<(), LimitError>> {
        Box::pin(self.check_request_at(bucket, limits, Utc::now()))
    }

    fn release(&self, slot: Slot) -> AiFuture<'_, ()> {
        Box::pin(async move {
            let removed = sqlx::query!("DELETE FROM ai.inflight WHERE token = $1", slot.token)
                .execute(self.db.pool())
                .await;
            if let Err(error) = removed {
                // the reaper takes the slot once it's stale
                tracing::warn!(
                    bucket = slot.bucket,
                    "the AI rate limiter failed to release a slot: {error}"
                );
            }
        })
    }
}
