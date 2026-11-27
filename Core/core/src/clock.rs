//! The core's one clock: the current time in Unix milliseconds.
//!
//! `std::time::SystemTime::now()` panics on `wasm32-unknown-unknown`, so there the clock reads
//! JavaScript's `Date.now()` instead.

/// Current time in Unix milliseconds, from the JavaScript engine the WebAssembly runs in.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) fn now_ms() -> i64 {
    // Whole milliseconds since 1970 (`Date.now()` is never fractional).
    js_sys::Date::now() as i64
}

/// Current time in Unix milliseconds (`0` if the system clock is before 1970).
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::now_ms;

    #[test]
    fn now_is_the_system_clock_in_milliseconds() {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let now = now_ms();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        assert!(
            before <= now && now <= after,
            "{before} <= {now} <= {after}"
        );
        // Milliseconds, not seconds or nanoseconds: after 2020 and before 2200.
        assert!(now > 1_577_836_800_000 && now < 7_258_118_400_000);
    }
}
