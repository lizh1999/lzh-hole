//! Production host pacing, Retry-After and rolling operation budgets.

use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::transport::NtfyError;

/// Minimum interval between every subscribe, reconnect and publish operation.
pub const MIN_HOST_INTERVAL: Duration = Duration::from_secs(30);
/// Longest automatic reconnect delay. Every delay is also bounded by the daily budget.
pub const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(15 * 60);
/// Fallback used for a 429 without a usable Retry-After value.
pub const MISSING_RETRY_AFTER_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// Default maximum number of HTTP operations in any rolling 24 hour window.
pub const DEFAULT_OPERATION_BUDGET: u32 = 128;
pub(crate) const OPERATION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
const PACING_SNAPSHOT_VERSION: u32 = 1;

/// Non-secret wall-clock representation used to preserve pacing across process
/// restarts. Monotonic clocks still drive all waits inside a running process.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PacingSnapshot {
    pub(crate) version: u32,
    pub(crate) operation_starts_unix_ms: Vec<u64>,
    pub(crate) not_before_unix_ms: Option<u64>,
    pub(crate) reason: Option<String>,
}

impl PacingSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            version: PACING_SNAPSHOT_VERSION,
            operation_starts_unix_ms: Vec::new(),
            not_before_unix_ms: None,
            reason: None,
        }
    }

    pub(crate) fn validate(&self, maximum: u32) -> Result<(), String> {
        if self.version != PACING_SNAPSHOT_VERSION {
            return Err(format!(
                "unsupported pacing snapshot version {}",
                self.version
            ));
        }
        if self.operation_starts_unix_ms.len() > maximum as usize {
            return Err("pacing snapshot contains more starts than the budget".to_owned());
        }
        if self
            .reason
            .as_ref()
            .is_some_and(|reason| reason.len() > 4096)
        {
            return Err("pacing snapshot reason exceeds 4096 bytes".to_owned());
        }
        Ok(())
    }
}

fn unix_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// Parse Retry-After delta-seconds or HTTP-date without producing a negative wait.
pub(crate) fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return value.parse::<u64>().ok().map(Duration::from_secs);
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(at.duration_since(now).unwrap_or(Duration::ZERO))
}

pub(crate) fn reconnect_delay(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(5);
    MIN_HOST_INTERVAL
        .checked_mul(1u32 << shift)
        .unwrap_or(MAX_RECONNECT_DELAY)
        .min(MAX_RECONNECT_DELAY)
}

/// Per-host operation gate shared by the initial subscribe, reconnects and posts.
#[derive(Debug, Default)]
pub(crate) struct HostGate {
    last_start: Option<Instant>,
    not_before: Option<Instant>,
}

impl HostGate {
    pub(crate) fn ready_at(&self, now: Instant) -> Result<Instant, NtfyError> {
        let interval_at = match self.last_start {
            Some(last) => Some(
                last.checked_add(MIN_HOST_INTERVAL)
                    .ok_or(NtfyError::ScheduleOverflow)?,
            ),
            None => None,
        };
        Ok(interval_at
            .into_iter()
            .chain(self.not_before)
            .fold(now, Instant::max))
    }

    pub(crate) fn note_start(&mut self, now: Instant) {
        self.last_start = Some(now);
    }

    pub(crate) fn defer(&mut self, now: Instant, delay: Duration) -> Result<(), NtfyError> {
        let at = now.checked_add(delay).ok_or(NtfyError::ScheduleOverflow)?;
        self.not_before = Some(self.not_before.map_or(at, |old| old.max(at)));
        Ok(())
    }

    pub(crate) fn remaining(&self, now: Instant) -> Result<Duration, NtfyError> {
        Ok(self.ready_at(now)?.saturating_duration_since(now))
    }

    pub(crate) fn restore(
        &mut self,
        not_before_unix_ms: Option<u64>,
        now: Instant,
        wall_now: SystemTime,
    ) -> Result<(), NtfyError> {
        if let Some(value) = not_before_unix_ms {
            let at = UNIX_EPOCH + Duration::from_millis(value);
            let delay = at.duration_since(wall_now).unwrap_or(Duration::ZERO);
            self.defer(now, delay)?;
        }
        Ok(())
    }

    pub(crate) fn not_before_unix_ms(
        &self,
        now: Instant,
        wall_now: SystemTime,
    ) -> Result<Option<u64>, NtfyError> {
        let delay = self.remaining(now)?;
        if delay.is_zero() {
            return Ok(None);
        }
        let at = wall_now
            .checked_add(delay)
            .ok_or(NtfyError::ScheduleOverflow)?;
        Ok(Some(unix_ms(at)))
    }
}

/// A rolling, rather than fixed-window, daily bound on actual HTTP attempts.
#[derive(Debug)]
pub(crate) struct OperationBudget {
    starts: VecDeque<Instant>,
    maximum: u32,
}

impl OperationBudget {
    pub(crate) fn new(maximum: u32) -> Self {
        Self {
            starts: VecDeque::new(),
            maximum,
        }
    }

    pub(crate) fn reserve(&mut self, now: Instant) -> Result<(), NtfyError> {
        while self
            .starts
            .front()
            .is_some_and(|start| now.duration_since(*start) >= OPERATION_WINDOW)
        {
            self.starts.pop_front();
        }
        if self.starts.len() >= self.maximum as usize {
            return Err(NtfyError::DailyBudgetExhausted(self.maximum));
        }
        self.starts.push_back(now);
        Ok(())
    }

    /// Earliest delay until the oldest operation leaves this same rolling window.
    pub(crate) fn recovery_delay(&self, now: Instant) -> Option<Duration> {
        if self.starts.len() < self.maximum as usize {
            return None;
        }
        self.starts
            .front()
            .map(|oldest| OPERATION_WINDOW.saturating_sub(now.duration_since(*oldest)))
    }

    pub(crate) fn restore(&mut self, starts_unix_ms: &[u64], now: Instant, wall_now: SystemTime) {
        for value in starts_unix_ms {
            let started = UNIX_EPOCH + Duration::from_millis(*value);
            let age = wall_now.duration_since(started).unwrap_or(Duration::ZERO);
            if age >= OPERATION_WINDOW {
                continue;
            }
            let monotonic = now.checked_sub(age).unwrap_or(now);
            self.starts.push_back(monotonic);
        }
        self.starts.make_contiguous().sort();
    }

    pub(crate) fn starts_unix_ms(&self, now: Instant, wall_now: SystemTime) -> Vec<u64> {
        self.starts
            .iter()
            .map(|started| {
                let age = now.saturating_duration_since(*started);
                unix_ms(wall_now.checked_sub(age).unwrap_or(UNIX_EPOCH))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    #[test]
    fn host_gate_paces_every_operation_and_obeys_retry_after() {
        let start = Instant::now();
        let mut gate = HostGate::default();
        assert_eq!(gate.ready_at(start).unwrap(), start);
        gate.note_start(start);
        assert_eq!(
            gate.ready_at(start + Duration::from_secs(1)).unwrap(),
            start + MIN_HOST_INTERVAL
        );
        gate.defer(start, Duration::from_secs(120)).unwrap();
        assert_eq!(
            gate.ready_at(start + MIN_HOST_INTERVAL).unwrap(),
            start + Duration::from_secs(120)
        );
        assert_eq!(reconnect_delay(1), Duration::from_secs(30));
        assert_eq!(reconnect_delay(2), Duration::from_secs(60));
        assert_eq!(reconnect_delay(16), MAX_RECONNECT_DELAY);
    }

    #[test]
    fn rolling_daily_budget_is_bounded_and_expires() {
        let start = Instant::now();
        let mut budget = OperationBudget::new(2);
        budget.reserve(start).unwrap();
        budget.reserve(start + Duration::from_secs(30)).unwrap();
        assert!(matches!(
            budget.reserve(start + Duration::from_secs(60)),
            Err(NtfyError::DailyBudgetExhausted(2))
        ));
        assert_eq!(
            budget.recovery_delay(start + Duration::from_secs(60)),
            Some(OPERATION_WINDOW - Duration::from_secs(60))
        );
        budget.reserve(start + OPERATION_WINDOW).unwrap();
    }

    #[test]
    fn retry_after_accepts_delta_and_http_date() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(parse_retry_after("45", now), Some(Duration::from_secs(45)));
        let later = httpdate::fmt_http_date(now + Duration::from_secs(60));
        assert_eq!(
            parse_retry_after(&later, now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(parse_retry_after("not-a-date", now), None);
    }
}
