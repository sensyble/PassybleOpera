//! Per-device usage counts, to suggest the most used logins first. Each device's counts are a
//! separate blob sealed with the vault key, so recording a use never touches an item's version.
//! Merges take the larger count and later time per item, so they commute and never lose a use.
//! Ranking is a frecency with a half-life of [`USAGE_HALF_LIFE_MS`] and a log-scaled count.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// Uses fade by half every 30 days.
pub const USAGE_HALF_LIFE_MS: i64 = 30 * DAY_MS;

/// At most this many devices' usage is kept per vault; the least recently written are dropped first.
pub const MAX_USAGE_DEVICES: usize = 16;

/// Usage-only changes don't start a sync of their own; they go with the next sync, or after this long
/// at the latest ([`crate::Vault::usage_sync_due`]).
pub const USAGE_SYNC_INTERVAL_MS: i64 = 6 * 60 * 60 * 1000;

/// Uses of the same item this close together count once (one sign-in may fill and then copy).
pub const USE_DEDUPE_MS: i64 = 60 * 1000;

/// One device's uses of one item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct UseCount {
    #[serde(rename = "n")]
    pub count: u64,
    /// Unix milliseconds.
    #[serde(rename = "t")]
    pub last_used: i64,
}

impl UseCount {
    fn merge(&mut self, other: &UseCount) {
        self.count = self.count.max(other.count);
        self.last_used = self.last_used.max(other.last_used);
    }
}

/// One device's counts (the sealed contents of its usage blob), by item id.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct DeviceUsage {
    #[serde(default)]
    pub items: BTreeMap<String, UseCount>,
}

impl DeviceUsage {
    /// Grow-only merge: per item the larger count and the later time.
    pub fn merge(&mut self, other: &DeviceUsage) {
        for (id, theirs) in &other.items {
            self.items.entry(id.clone()).or_default().merge(theirs);
        }
    }

    /// Records one use of `item_id` at `now` (uses within [`USE_DEDUPE_MS`] of the last count once).
    pub fn record(&mut self, item_id: &str, now: i64) {
        let entry = self.items.entry(item_id.to_string()).or_default();
        if entry.count == 0 || now.saturating_sub(entry.last_used) >= USE_DEDUPE_MS {
            entry.count = entry.count.saturating_add(1);
        }
        entry.last_used = entry.last_used.max(now);
    }
}

/// How much a login was used, over every device (the sum of their counts).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ItemUsage {
    /// Uses on every device.
    pub count: u64,
    /// The last use on any device (Unix milliseconds), 0 if never used.
    pub last_used: i64,
    /// [`usage_rank`]: higher is used more (and more recently). 0 if never used.
    pub rank: i64,
}

/// The weight of `count` uses: log-scaled (1 use = 1, 3 = 2, 7 = 3, 1023 = 10).
fn weight(count: u64) -> f64 {
    ((count as f64) + 1.0).log2()
}

/// The frecency of an item at `now`: each device's weighted count ([`weight`]) halved per half-life since
/// that device last used it. 0 if never used.
pub(crate) fn frecency<'a>(uses: impl IntoIterator<Item = &'a UseCount>, now: i64) -> f64 {
    uses.into_iter()
        .filter(|u| u.count > 0)
        .map(|u| {
            let age = now.saturating_sub(u.last_used).max(0) as f64;
            weight(u.count) * (-age / USAGE_HALF_LIFE_MS as f64).exp2()
        })
        .sum()
}

/// A time-independent sort key for [`frecency`]: every device's term decays at the same rate, so items
/// keep their order as time passes. `rank = now + H * log2(frecency(now))` for any `now` (H the
/// half-life). Higher ranks first; 0 when never used.
pub(crate) fn usage_rank<'a>(uses: impl IntoIterator<Item = &'a UseCount>) -> i64 {
    let uses: Vec<&UseCount> = uses.into_iter().filter(|u| u.count > 0).collect();
    let Some(latest) = uses.iter().map(|u| u.last_used).max() else {
        return 0;
    };
    // Relative to the latest use, so nothing overflows.
    let sum = frecency(uses.iter().copied(), latest);
    let shift = USAGE_HALF_LIFE_MS as f64 * sum.log2();
    // `as` saturates (and maps NaN to 0, which `max` lifts to 1).
    ((latest as f64 + shift).round() as i64).max(1)
}

/// The total usage of one item over the given devices' counts.
pub(crate) fn item_usage<'a>(uses: impl IntoIterator<Item = &'a UseCount> + Clone) -> ItemUsage {
    let mut count = 0u64;
    let mut last_used = 0i64;
    for u in uses.clone() {
        count = count.saturating_add(u.count);
        last_used = last_used.max(u.last_used);
    }
    ItemUsage {
        count,
        last_used,
        rank: usage_rank(uses),
    }
}

/// [`frecency`] of an [`ItemUsage::rank`] at `now` (Unix milliseconds). 0 for a login never used.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn usage_frecency(rank: i64, now_ms: i64) -> f64 {
    if rank <= 0 {
        return 0.0;
    }
    ((rank as f64 - now_ms as f64) / USAGE_HALF_LIFE_MS as f64).exp2()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uses(entries: &[(u64, i64)]) -> Vec<UseCount> {
        entries
            .iter()
            .map(|&(count, last_used)| UseCount { count, last_used })
            .collect()
    }

    fn device(entries: &[(&str, u64, i64)]) -> DeviceUsage {
        DeviceUsage {
            items: entries
                .iter()
                .map(|&(id, count, last_used)| (id.to_string(), UseCount { count, last_used }))
                .collect(),
        }
    }

    #[test]
    fn merging_commutes_and_repeats_harmlessly() {
        let a = device(&[("x", 3, 100), ("y", 1, 50)]);
        let b = device(&[("x", 2, 200), ("z", 4, 10)]);
        let c = device(&[("y", 5, 20), ("z", 1, 300)]);
        let merged = |parts: &[&DeviceUsage]| {
            let mut m = DeviceUsage::default();
            for p in parts {
                m.merge(p);
            }
            m
        };
        let abc = merged(&[&a, &b, &c]);
        assert_eq!(abc, merged(&[&c, &b, &a]));
        assert_eq!(abc, merged(&[&b, &a, &c, &a, &b]));
        assert_eq!(abc, merged(&[&abc, &abc]));
        assert_eq!(abc, device(&[("x", 3, 200), ("y", 5, 50), ("z", 4, 300)]));
        for part in [&a, &b, &c] {
            for (id, u) in &part.items {
                assert!(abc.items[id].count >= u.count && abc.items[id].last_used >= u.last_used);
            }
        }
    }

    #[test]
    fn uses_close_together_count_once() {
        let mut d = DeviceUsage::default();
        d.record("x", 1_000_000);
        d.record("x", 1_000_000 + USE_DEDUPE_MS - 1);
        assert_eq!(d.items["x"].count, 1);
        assert_eq!(d.items["x"].last_used, 1_000_000 + USE_DEDUPE_MS - 1);
        d.record("x", 1_000_000 + 2 * USE_DEDUPE_MS);
        assert_eq!(d.items["x"].count, 2);
        d.record("x", 5);
        assert_eq!(d.items["x"].last_used, 1_000_000 + 2 * USE_DEDUPE_MS);
    }

    #[test]
    fn rank_orders_like_frecency_at_any_time() {
        let now = 1_760_000_000_000;
        let cases = [
            uses(&[(1, now)]),
            uses(&[(50, now - 90 * DAY_MS)]),
            uses(&[(3, now - 2 * DAY_MS)]),
            uses(&[(7, now - 30 * DAY_MS)]),
            uses(&[(2, now - 5 * DAY_MS), (2, now - DAY_MS)]),
            uses(&[(1000, now - 400 * DAY_MS)]),
            uses(&[]),
        ];
        let mut by_rank: Vec<usize> = (0..cases.len()).collect();
        by_rank.sort_by_key(|&i| std::cmp::Reverse(usage_rank(&cases[i])));
        for later in [0, DAY_MS, 365 * DAY_MS] {
            let mut by_frecency: Vec<usize> = (0..cases.len()).collect();
            by_frecency.sort_by(|&a, &b| {
                frecency(&cases[b], now + later).total_cmp(&frecency(&cases[a], now + later))
            });
            assert_eq!(by_rank, by_frecency, "{later}");
        }
        let r = usage_rank(&cases[2]);
        assert!((usage_frecency(r, now) - frecency(&cases[2], now)).abs() < 1e-9);
        assert_eq!(usage_rank(&cases[6]), 0);
        assert_eq!(usage_frecency(0, now), 0.0);
        assert!(usage_rank(&cases[0]) > usage_rank(&cases[5]));
        assert!(usage_rank(&uses(&[(5, now)])) > usage_rank(&uses(&[(1, now)])));
        assert!(usage_rank(&cases[4]) > usage_rank(&uses(&[(2, now - DAY_MS)])));
    }

    #[test]
    fn ranks_survive_extreme_times() {
        for t in [0, 1, -5, i64::MAX, i64::MIN] {
            let r = usage_rank(&uses(&[(u64::MAX, t), (1, t)]));
            assert!(r >= 1, "{t}: {r}");
        }
        let total = item_usage(&uses(&[(u64::MAX, 1), (5, 9)]));
        assert_eq!((total.count, total.last_used), (u64::MAX, 9));
    }
}
