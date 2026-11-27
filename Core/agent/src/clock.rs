//! The agent's clocks: a monotonic [`Instant`] for timers and the wall clock in Unix milliseconds.
//!
//! std's clocks panic on `wasm32-unknown-unknown`, so there [`Instant`] and [`SystemTime`] come
//! from `web-time`. Other targets use std's types.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use web_time::{Instant, SystemTime, UNIX_EPOCH};

/// Where the agent reads the time.
pub trait Clock: Send + Sync {
    /// Now, on a monotonic clock (only differences between two of these mean anything).
    fn now(&self) -> Instant;
    /// Now in Unix milliseconds (`0` before 1970).
    fn unix_ms(&self) -> i64;
}

/// The system's clocks (std; `performance.now()` and `Date.now()` in the browser).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn unix_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to ([`ManualClock::advance`]): for tests of timers, and for a
/// host that drives the time itself. Both readings move together.
#[derive(Debug)]
pub struct ManualClock {
    start: Instant,
    unix_start_ms: i64,
    elapsed_ms: AtomicU64,
}

impl ManualClock {
    /// A clock standing at `unix_ms` (Unix milliseconds).
    pub fn new(unix_ms: i64) -> ManualClock {
        ManualClock {
            start: Instant::now(),
            unix_start_ms: unix_ms,
            elapsed_ms: AtomicU64::new(0),
        }
    }

    /// A clock standing at the system's time now.
    pub fn at_system_time() -> ManualClock {
        ManualClock::new(SystemClock.unix_ms())
    }

    /// Moves both readings on by `by` (whole milliseconds).
    pub fn advance(&self, by: Duration) {
        self.elapsed_ms
            .fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }

    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.elapsed_ms.load(Ordering::SeqCst))
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.start + self.elapsed()
    }

    fn unix_ms(&self) -> i64 {
        self.unix_start_ms
            .saturating_add(self.elapsed().as_millis() as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_is_std() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let unix = SystemClock.unix_ms();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        assert!(before <= unix && unix <= after);
        let a = SystemClock.now();
        let b = SystemClock.now();
        assert!(b >= a, "monotonic");
    }

    #[test]
    fn a_manual_clock_moves_only_when_told_and_both_readings_together() {
        let clock = ManualClock::new(1_700_000_000_000);
        let t0 = clock.now();
        assert_eq!(clock.unix_ms(), 1_700_000_000_000);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(clock.now(), t0, "real time passing doesn't move it");
        clock.advance(Duration::from_secs(90));
        assert_eq!(clock.now().duration_since(t0), Duration::from_secs(90));
        assert_eq!(clock.unix_ms(), 1_700_000_090_000);
        // Sub-millisecond steps are dropped, so the two readings never disagree.
        clock.advance(Duration::from_micros(999));
        assert_eq!(clock.now().duration_since(t0), Duration::from_secs(90));
    }

    #[test]
    fn a_manual_clock_can_start_at_the_system_time() {
        let clock = ManualClock::at_system_time();
        assert!((clock.unix_ms() - SystemClock.unix_ms()).abs() < 5_000);
    }
}
