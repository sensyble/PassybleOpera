//! Step timings of slow requests (Windows Hello, unlock, fill), one line per step:
//! `2026-10-24T09:12:03.418Z app #7 hello: dialog answered +912.4ms (+880.1ms)`.
//! Lines go to stderr in debug builds and to the file named by `PASSYBLE_TIMING_LOG`. Step names
//! are fixed texts, never a secret, username, URL or item name.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::clock::{Instant, SystemTime, UNIX_EPOCH};

/// The environment variable naming the file timing lines are appended to.
pub const ENV: &str = "PASSYBLE_TIMING_LOG";

struct Sink {
    file: Option<PathBuf>,
    stderr: bool,
}

static SINK: OnceLock<Sink> = OnceLock::new();
static TAG: OnceLock<&'static str> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(1);
/// One writer at a time, so lines of concurrent traces don't interleave.
static WRITE: Mutex<()> = Mutex::new(());

/// Without the `native` feature timing is always off.
fn sink() -> &'static Sink {
    SINK.get_or_init(|| Sink {
        file: std::env::var_os(ENV)
            .filter(|v| !v.is_empty() && cfg!(feature = "native"))
            .map(PathBuf::from),
        stderr: cfg!(debug_assertions) && !cfg!(test) && cfg!(feature = "native"),
    })
}

/// Names this process in the lines (`app`, `host`); the default is `app`. Call once at start-up.
pub fn set_process(tag: &'static str) {
    let _ = TAG.set(tag);
}

/// Whether timing lines go anywhere; when not, traces cost an `Instant` and nothing else.
pub fn enabled() -> bool {
    let sink = sink();
    sink.stderr || sink.file.is_some()
}

/// The steps of one request.
#[derive(Debug)]
pub struct Trace {
    id: u64,
    start: Instant,
    /// Nanoseconds after `start` of the previous mark.
    last: AtomicU64,
}

impl Trace {
    /// A new trace, its first line being `step`.
    pub fn begin(step: &str) -> Arc<Trace> {
        let trace = Arc::new(Trace {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            start: Instant::now(),
            last: AtomicU64::new(0),
        });
        trace.mark(step);
        trace
    }

    /// Writes `step` with the time since the trace began and since its previous step.
    pub fn mark(&self, step: &str) {
        if !enabled() {
            return;
        }
        let total = self.start.elapsed().as_nanos() as u64;
        let previous = self.last.swap(total, Ordering::Relaxed);
        let line = format_line(
            SystemTime::now(),
            TAG.get().copied().unwrap_or("app"),
            self.id,
            step,
            total,
            total.saturating_sub(previous),
        );
        write(&line);
    }

    /// Milliseconds since the trace began.
    pub fn elapsed_ms(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1000.0
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<Trace>>> = const { RefCell::new(None) };
}

/// The trace of the request this thread serves, to hand to a thread it starts ([`enter`]).
pub fn current() -> Option<Arc<Trace>> {
    CURRENT.with(|c| c.borrow().clone())
}

/// Makes `trace` this thread's trace until the guard is dropped (then the previous one again).
pub fn enter(trace: Option<Arc<Trace>>) -> Entered {
    Entered(CURRENT.with(|c| c.replace(trace)))
}

/// See [`enter`].
pub struct Entered(Option<Arc<Trace>>);

impl Drop for Entered {
    fn drop(&mut self) {
        let previous = self.0.take();
        CURRENT.with(|c| *c.borrow_mut() = previous);
    }
}

/// Marks `step` in this thread's trace; nothing without one.
pub fn mark(step: &str) {
    if let Some(trace) = current() {
        trace.mark(step);
    }
}

/// The last step of a request: `"<method>: answered"`, or `"<method>: answered with an error
/// (<code>)"`. Only a plain protocol code is written, never an error message (which can name a
/// site or an item); anything else is `(other)`.
pub fn answered(method: &str, error_code: Option<&str>) -> String {
    match error_code {
        None => format!("{method}: answered"),
        Some(code) => format!("{method}: answered with an error ({})", safe_code(code)),
    }
}

/// `code` if it looks like a protocol error code, else `"other"`.
pub fn safe_code(code: &str) -> &str {
    let plain = !code.is_empty()
        && code.len() <= 32
        && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    if plain {
        code
    } else {
        "other"
    }
}

fn write(line: &str) {
    let sink = sink();
    let _guard = WRITE.lock().unwrap_or_else(|p| p.into_inner());
    if sink.stderr {
        eprint!("pass-timing: {line}");
    }
    #[cfg(feature = "native")]
    if let Some(file) = &sink.file {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// One line, newline included. `total` and `delta` in nanoseconds.
fn format_line(
    now: SystemTime,
    process: &str,
    id: u64,
    step: &str,
    total: u64,
    delta: u64,
) -> String {
    // A step name with a line break must not fake another line.
    let step = step.replace(['\r', '\n'], " ");
    format!(
        "{} {process} #{id} {step} +{:.1}ms (+{:.1}ms)\n",
        iso_millis(now),
        total as f64 / 1e6,
        delta as f64 / 1e6
    )
}

/// `2026-10-24T09:12:03.418Z` (UTC, milliseconds).
fn iso_millis(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn lines_say_when_which_step_and_how_long() {
        let t = UNIX_EPOCH + Duration::from_millis(1_791_571_932_418);
        assert_eq!(iso_millis(t), "2026-10-09T18:52:12.418Z");
        assert_eq!(
            format_line(
                t,
                "app",
                7,
                "hello: dialog answered",
                912_400_000,
                880_100_000
            ),
            "2026-10-09T18:52:12.418Z app #7 hello: dialog answered +912.4ms (+880.1ms)\n"
        );
        // One line, whatever the step says.
        assert_eq!(
            format_line(t, "host", 1, "a\nb", 0, 0),
            "2026-10-09T18:52:12.418Z host #1 a b +0.0ms (+0.0ms)\n"
        );
    }

    #[test]
    fn a_failed_request_ends_with_its_error_code_never_a_message() {
        assert_eq!(answered("passkey.find", None), "passkey.find: answered");
        assert_eq!(
            answered("passkey.find", Some("locked")),
            "passkey.find: answered with an error (locked)"
        );
        assert_eq!(
            answered("passkey.get", Some("not_found")),
            "passkey.get: answered with an error (not_found)"
        );
        // Anything that isn't a plain code (a message, a name, a URL) stays out of the log.
        for odd in [
            "",
            "no passkey for this site in Passyble",
            "https://example.com",
            "Locked",
            "alice@example.com",
            "a\nb",
            "x".repeat(33).as_str(),
        ] {
            assert_eq!(
                answered("passkey.get", Some(odd)),
                "passkey.get: answered with an error (other)",
                "{odd:?}"
            );
        }
    }

    #[test]
    fn the_trace_follows_the_thread_it_is_entered_on() {
        assert!(current().is_none());
        let trace = Trace::begin("request received");
        {
            let _entered = enter(Some(trace.clone()));
            assert_eq!(current().map(|t| t.id), Some(trace.id));
            let handed = current();
            let seen = std::thread::spawn(move || {
                assert!(current().is_none(), "a new thread has none of its own");
                let _entered = enter(handed);
                mark("on another thread");
                current().map(|t| t.id)
            })
            .join()
            .unwrap();
            assert_eq!(seen, Some(trace.id));
            {
                let _inner = enter(None);
                assert!(current().is_none());
            }
            assert!(current().is_some(), "the outer trace again");
        }
        assert!(current().is_none());
    }
}
