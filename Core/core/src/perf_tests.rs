//! Performance on low-end phones: demo vaults of 50, 1 000 and 5 000 items plus shared vaults.
//! `perf_guard_*` run in every test run with generous limits, to catch work that grows out of
//! proportion. `perf_bench_*` are ignored; run them in an optimized build, one at a time:
//! `cargo test -p pass-core --profile perf --lib perf_bench -- --ignored --nocapture --test-threads=1`

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::model::{CardData, IdentityData};
use crate::share::{MemberRole, SharedKind};
use crate::{AndroidApp, Item, ItemKind, KdfParams, Passkey, PasswordHistoryEntry, Vault};

struct Counting;

/// Counting is on only while a measurement runs: a shared counter that every allocation of every
/// thread writes would slow down (and misstate) the timings of work spread over threads.
static COUNTING: AtomicBool = AtomicBool::new(false);
static ALL_LIVE: AtomicIsize = AtomicIsize::new(0);
static ALL_PEAK: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn note(delta: isize) {
    if !COUNTING.load(Ordering::Relaxed) {
        return;
    }
    let now = ALL_LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
    ALL_PEAK.fetch_max(now, Ordering::Relaxed);
    // `try_with`: a thread being torn down has no counters left; its frees just aren't counted.
    let _ = LIVE.try_with(|live| {
        let now = live.get() + delta;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now);
            }
        });
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            note(layout.size() as isize);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            note(layout.size() as isize);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        note(-(layout.size() as isize));
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            note(new_size as isize - layout.size() as isize);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Runs `f` with the allocations counted.
fn counting<T>(f: impl FnOnce() -> T) -> T {
    let was = COUNTING.swap(true, Ordering::Relaxed);
    let out = f();
    COUNTING.store(was, Ordering::Relaxed);
    out
}

/// The most this thread had allocated at once while `f` ran, above what it held before (bytes).
/// Work `f` hands to other threads isn't counted: for the guards, which run beside other tests.
fn thread_peak_of<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(base));
    let out = counting(f);
    let peak = PEAK.with(Cell::get) - base;
    (out, peak.max(0) as usize)
}

/// The most the process had allocated at once while `f` ran, above what it held before (bytes).
/// For the benchmarks (one test at a time).
fn peak_of<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = ALL_LIVE.load(Ordering::Relaxed);
    ALL_PEAK.store(base, Ordering::Relaxed);
    let out = counting(f);
    let peak = ALL_PEAK.load(Ordering::Relaxed) - base;
    (out, peak.max(0) as usize)
}

/// Bytes the process still holds after `f` returned what it built (kept alive). For the
/// benchmarks.
fn retained_by<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = ALL_LIVE.load(Ordering::Relaxed);
    let out = counting(f);
    let now = ALL_LIVE.load(Ordering::Relaxed) - base;
    (out, now.max(0) as usize)
}

const MB: f64 = 1024.0 * 1024.0;

/// A small deterministic generator (no secrets: demo data only).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn word(&mut self) -> &'static str {
        WORDS[self.below(WORDS.len() as u64) as usize]
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

const WORDS: &[&str] = &[
    "github", "gitlab", "google", "mail", "bank", "shop", "cloud", "music", "video", "news",
    "travel", "hotel", "flight", "health", "school", "games", "photo", "forum", "chat", "maps",
    "store", "market", "energy", "water", "phone", "fiber", "insure", "taxes", "city", "library",
    "pizza", "coffee", "books", "sport", "fitness", "cinema", "tickets", "parking", "rental",
    "garden", "pets", "crypto", "notes", "drive", "office", "design", "code", "deploy", "status",
    "paypal", "amazon", "netflix", "spotify", "dropbox", "slack", "zoom", "steam", "reddit",
];
const TLDS: &[&str] = &[
    "com", "net", "org", "io", "co.uk", "de", "fr", "com.au", "app", "dev",
];

fn domain(rng: &mut Lcg, i: usize) -> String {
    let tld = TLDS[rng.below(TLDS.len() as u64) as usize];
    // Mostly distinct sites, as in a real vault; a few share one (work and personal accounts).
    format!("{}{}.{tld}", rng.word(), i % 1500)
}

fn demo_item(rng: &mut Lcg, i: usize) -> Item {
    let roll = rng.below(100);
    let title = format!("{} {}", rng.word(), i);
    let created = 1_700_000_000_000 + i as i64 * 60_000;
    let tags = if rng.below(3) == 0 {
        vec![format!("{}/{}", rng.word(), rng.word())]
    } else {
        Vec::new()
    };
    let base = Item {
        title,
        tags,
        created_at: created,
        favorite: rng.below(20) == 0,
        ..Default::default()
    };
    match roll {
        0..=75 => {
            let site = domain(rng, i);
            let mut urls = vec![format!(
                "https://{}{site}/login",
                if rng.below(4) == 0 { "accounts." } else { "" }
            )];
            if rng.below(5) == 0 {
                urls.push(format!("https://{site}"));
            }
            // Some reused and some weak passwords, as the health report expects to find.
            let password = match rng.below(10) {
                0 => "Summer2024!".to_string(),
                1 => format!("{}{}", rng.word(), rng.below(100)),
                _ => format!("Demo-{}-{}-{}", rng.next(), rng.word(), rng.next()),
            };
            let history = (0..rng.below(4))
                .map(|h| PasswordHistoryEntry {
                    password: format!("Old-{}-{h}-{}", rng.next(), rng.word()),
                    replaced_at: created - (h as i64 + 1) * 86_400_000,
                })
                .collect();
            let passkeys = if rng.below(10) == 0 {
                vec![Passkey {
                    credential_id: rng.bytes(16),
                    rp_id: site.clone(),
                    rp_name: Some(rng.word().to_string()),
                    user_handle: rng.bytes(16),
                    user_name: format!("kim{i}@example.com"),
                    user_display_name: "Kim Demo".into(),
                    private_key_pkcs8: rng.bytes(138),
                    sign_count: 0,
                    discoverable: true,
                    created_at: created,
                }]
            } else {
                Vec::new()
            };
            let android_apps = if rng.below(8) == 0 {
                vec![AndroidApp {
                    package: format!("com.{}.android", rng.word()),
                    cert_sha256: Some(crate::encoding::hex(&rng.bytes(32))),
                    ..Default::default()
                }]
            } else {
                Vec::new()
            };
            let totp = (rng.below(5) == 0).then(|| "JBSWY3DPEHPK3PXP".to_string());
            Item {
                kind: ItemKind::Login,
                username: format!("kim.demo{}@example.com", i % 7),
                password,
                urls,
                android_apps,
                totp,
                passkeys,
                password_history: history,
                notes: if rng.below(4) == 0 {
                    format!("Security question: {} {}", rng.word(), rng.word())
                } else {
                    String::new()
                },
                ..base
            }
        }
        76..=85 => Item {
            kind: ItemKind::Note,
            notes: (0..40).map(|_| rng.word()).collect::<Vec<_>>().join(" "),
            ..base
        },
        86..=92 => Item {
            kind: ItemKind::Card,
            card: Some(CardData {
                cardholder_name: "Kim Demo".into(),
                number: "4111111111111111".into(),
                expiry_month: 1 + rng.below(12) as u32,
                expiry_year: 2030,
                security_code: "123".into(),
                ..Default::default()
            }),
            ..base
        },
        _ => Item {
            kind: ItemKind::Identity,
            identity: Some(IdentityData {
                first_name: "Kim".into(),
                last_name: "Demo".into(),
                email: format!("kim{i}@example.com"),
                company: format!("{} Ltd", rng.word()),
                ..Default::default()
            }),
            ..base
        },
    }
}

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

/// A personal vault with `n` demo items (cheap KDF; the benchmark re-keys where it matters).
fn demo_vault(n: usize, seed: u64, kdf: KdfParams) -> Arc<Vault> {
    let vault = Vault::create_with_kdf("demo master password", "phone-1", kdf).unwrap();
    let mut rng = Lcg(seed);
    for i in 0..n {
        vault.upsert(demo_item(&mut rng, i)).unwrap();
    }
    vault
}

struct Shared {
    home: Arc<Vault>,
    files: Vec<Vec<u8>>,
}

/// Three shared vaults of `n` items made by Alice with Bob as an editor; Bob's home vault opens them.
fn demo_shared(n: usize) -> Shared {
    let alice = Vault::create_with_kdf("demo master password", "alice-laptop", fast_kdf()).unwrap();
    let bob = Vault::create_with_kdf("demo master password", "bob-phone", fast_kdf()).unwrap();
    let alice_keys = alice.ensure_user_keyset("acc_alice").unwrap();
    let bob_public = bob.ensure_user_keyset("acc_bob").unwrap().public_keys();
    let files = (0..3)
        .map(|v| {
            let shared = Vault::create_shared(
                &alice_keys,
                SharedKind::Org,
                Some("org_demo".into()),
                "alice-laptop",
            )
            .unwrap();
            shared
                .add_member_unchecked(bob_public.clone(), MemberRole::Edit, None)
                .unwrap();
            let mut rng = Lcg(1000 + v);
            for i in 0..n {
                shared
                    .upsert(demo_item(&mut rng, 10_000 * (v as usize + 1) + i))
                    .unwrap();
            }
            shared.serialize().unwrap()
        })
        .collect();
    Shared { home: bob, files }
}

/// The median of `runs` timings of `f` (after one warm-up run).
/// What `f` returns is dropped after the clock stops: freeing a vault is not part of opening it.
fn median<T>(runs: usize, mut f: impl FnMut() -> T) -> Duration {
    std::hint::black_box(f());
    let mut times: Vec<Duration> = (0..runs)
        .map(|_| {
            let t = Instant::now();
            let out = std::hint::black_box(f());
            let took = t.elapsed();
            drop(out);
            took
        })
        .collect();
    times.sort();
    times[times.len() / 2]
}

/// Phone time from PC time: a low-end phone is about 6 to 10 times slower per core; the upper
/// end is used against the budgets.
const PHONE: f64 = 10.0;

fn report(name: &str, pc: Duration, budget_ms: Option<f64>) {
    let pc_ms = pc.as_secs_f64() * 1000.0;
    let phone = pc_ms * PHONE;
    let verdict = match budget_ms {
        Some(b) if phone <= b => format!("ok (budget {b} ms)"),
        Some(b) => format!("MISSED (budget {b} ms)"),
        None => String::new(),
    };
    println!("{name:<48} pc {pc_ms:>9.3} ms  phone ~{phone:>9.1} ms  {verdict}");
}

/// The queries a user types, one keystroke at a time.
const KEYSTROKES: &[&str] = &["g", "gi", "git", "gith", "githu", "github", "github 1"];

fn per_keystroke(mut f: impl FnMut(&str)) -> Duration {
    let total = median(5, || {
        for q in KEYSTROKES {
            f(q);
        }
    });
    total / KEYSTROKES.len() as u32
}

/// Groups as the apps hold them: the home vault and the open shared vaults.
fn groups_of(home: &Vault, shared: &[Arc<Vault>]) -> Vec<crate::VaultSummaries> {
    std::iter::once(home.vault_summaries())
        .chain(shared.iter().map(|s| s.vault_summaries()))
        .collect()
}

/// Saving after one edit seals that item only: every other item keeps its ciphertext, byte for byte.
#[test]
fn perf_guard_save_after_one_edit_reseals_one_item() {
    let vault = demo_vault(300, 7, fast_kdf());
    let before: serde_json::Value = serde_json::from_slice(&vault.serialize().unwrap()).unwrap();
    let mut item = vault.items().into_iter().next().unwrap();
    item.title.push_str(" (edited)");
    vault.upsert(item.clone()).unwrap();
    let after: serde_json::Value = serde_json::from_slice(&vault.serialize().unwrap()).unwrap();
    let ct = |v: &serde_json::Value| -> HashMap<String, String> {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["id"].as_str().unwrap().to_string(),
                    r["ct"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    };
    let (b, a) = (ct(&before), ct(&after));
    let changed: Vec<&String> = a.keys().filter(|id| b.get(*id) != a.get(*id)).collect();
    assert_eq!(changed, vec![&item.id]);
}

/// The operations of one keystroke and one page stay far from anything a phone would feel, even
/// in a debug build on a busy PC (limits about 20 times what they take here).
#[test]
fn perf_guard_per_keystroke_and_per_page_work() {
    let vault = demo_vault(1000, 11, fast_kdf());
    let groups = vec![vault.vault_summaries()];
    let search = per_keystroke(|q| {
        std::hint::black_box(crate::multi_search(groups.clone(), q.to_string()));
    });
    let index = crate::SearchIndex::new(groups.clone(), HashMap::new());
    let indexed = per_keystroke(|q| {
        std::hint::black_box(index.search(q.to_string()));
    });
    let vault_search = per_keystroke(|q| {
        std::hint::black_box(vault.search(q.to_string()));
    });
    let url = "https://accounts.github7.com/login";
    let for_url = median(5, || crate::multi_for_url(groups.clone(), url.to_string()));
    let id = vault.items()[0].id.clone();
    let lookalike = median(5, || {
        vault.lookalike_for_url("https://paypa1.com".into(), id.clone())
    });
    let save_check = median(5, || vault.lookalike_for_save("https://paypa1.com".into()));
    for (name, took, limit_ms) in [
        ("multi_search per keystroke, 1 000 items", search, 400),
        (
            "SearchIndex::search per keystroke, 1 000 items",
            indexed,
            100,
        ),
        (
            "Vault::search per keystroke, 1 000 items",
            vault_search,
            100,
        ),
        ("multi_for_url, 1 000 items", for_url, 400),
        ("lookalike_for_url, 1 000 items", lookalike, 50),
        ("lookalike_for_save, 1 000 items", save_check, 50),
    ] {
        assert!(
            took < Duration::from_millis(limit_ms),
            "{name} took {took:?} (limit {limit_ms} ms in a debug build)"
        );
    }
}

/// Unlocking, saving and merging a 1 000-item vault stay linear and light (debug build limits).
#[test]
fn perf_guard_unlock_save_merge() {
    let vault = demo_vault(1000, 13, fast_kdf());
    let file = vault.serialize().unwrap();
    let key = vault.export_vault_key();
    let unlock = median(3, || {
        Vault::unlock_with_key(file.clone(), key.clone(), "phone-1".into()).unwrap()
    });
    let mut item = vault.items().into_iter().next().unwrap();
    let save = median(3, || {
        item.title.push('!');
        vault.upsert(item.clone()).unwrap();
        vault.save_snapshot().unwrap()
    });
    let other = Vault::unlock_with_key(file.clone(), key.clone(), "laptop-1".into()).unwrap();
    for it in other.items().into_iter().take(50) {
        let mut it = it;
        it.notes.push_str(" laptop");
        other.upsert(it).unwrap();
    }
    let remote = other.serialize().unwrap();
    let merge = median(3, || vault.merge_remote(remote.clone()).unwrap());
    for (name, took, limit_ms) in [
        ("unlock with the key, 1 000 items", unlock, 3000),
        ("upsert + save_snapshot, 1 000 items", save, 1500),
        ("merge_remote, 1 000 items", merge, 3000),
    ] {
        assert!(
            took < Duration::from_millis(limit_ms),
            "{name} took {took:?} (limit {limit_ms} ms)"
        );
    }
    // Opening holds the file, its parse and the items: a few times the file, never dozens.
    // Measured on one thread: below the size whose records are decrypted on several.
    let small = demo_vault(400, 14, fast_kdf());
    let small_file = small.serialize().unwrap();
    let small_key = small.export_vault_key();
    let (_, peak) = thread_peak_of(|| {
        Vault::unlock_with_key(small_file.clone(), small_key.clone(), "phone-1".into()).unwrap()
    });
    let file_mb = small_file.len() as f64 / MB;
    assert!(
        (peak as f64) < 12.0 * small_file.len() as f64 + 8.0 * MB,
        "unlock peak {:.1} MB for a {file_mb:.1} MB file",
        peak as f64 / MB
    );
}

#[test]
#[ignore = "benchmark: run in an optimized build"]
fn perf_bench_unlock_with_master_password() {
    for n in [50usize, 1000, 5000] {
        let vault = demo_vault(n, 1, KdfParams::default());
        let file = vault.serialize().unwrap();
        let unlock = || {
            Vault::unlock(
                file.clone(),
                "demo master password".into(),
                "phone-1".into(),
            )
            .unwrap()
        };
        let took = median(3, unlock);
        let (_, peak) = peak_of(unlock);
        report(
            &format!("unlock (Argon2id 64 MiB t=3), {n} items"),
            took,
            Some(1500.0),
        );
        println!(
            "{:<48} peak {:.1} MB (budget 96 MB), file {:.2} MB",
            "",
            peak as f64 / MB,
            file.len() as f64 / MB
        );
        let key = vault.export_vault_key();
        // Timed without the allocation counting, which would slow the decrypting threads.
        let took = median(5, || {
            Vault::unlock_with_key(file.clone(), key.clone(), "phone-1".into()).unwrap()
        });
        let (_, peak) = peak_of(|| {
            Vault::unlock_with_key(file.clone(), key.clone(), "phone-1".into()).unwrap()
        });
        report(
            &format!("unlock with the device key, {n} items"),
            took,
            Some(300.0),
        );
        let (_, kept) = retained_by(|| {
            Vault::unlock_with_key(file.clone(), key.clone(), "phone-1".into()).unwrap()
        });
        println!(
            "{:<48} peak {:.1} MB, held while open {:.1} MB",
            "",
            peak as f64 / MB,
            kept as f64 / MB
        );
    }
}

#[test]
#[ignore = "benchmark: run in an optimized build"]
fn perf_bench_vault_operations() {
    let shared = demo_shared(500);
    let open: Vec<Arc<Vault>> = shared
        .files
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let t = median(5, || {
                Vault::open_shared_with_home(f.clone(), &shared.home, "acc_bob", "bob-phone")
                    .unwrap()
            });
            report(
                &format!("open_shared_with_home, vault {} (500 items)", i + 1),
                t,
                Some(100.0),
            );
            Vault::open_shared_with_home(f.clone(), &shared.home, "acc_bob", "bob-phone").unwrap()
        })
        .collect();
    for n in [50usize, 1000, 5000] {
        println!("-- {n} items (+ 3 shared vaults of 500) --");
        let vault = demo_vault(n, 2, fast_kdf());
        let file = vault.serialize().unwrap();
        let key = vault.export_vault_key();

        let mut item = vault.items().into_iter().nth(n / 2).unwrap();
        let t = median(9, || {
            item.title.push('!');
            vault.upsert(item.clone()).unwrap();
            vault.save_snapshot().unwrap()
        });
        report("upsert one item + save_snapshot", t, Some(200.0));

        let other = Vault::unlock_with_key(file.clone(), key.clone(), "laptop-1".into()).unwrap();
        for it in other.items().into_iter().take(n / 10) {
            let mut it = it;
            it.notes.push_str(" laptop");
            other.upsert(it).unwrap();
        }
        let remote = other.serialize().unwrap();
        let mut merges: Vec<Duration> = (0..5)
            .map(|_| {
                let copy =
                    Vault::unlock_with_key(file.clone(), key.clone(), "phone-1".into()).unwrap();
                let t = Instant::now();
                copy.merge_remote(remote.clone()).unwrap();
                t.elapsed()
            })
            .collect();
        merges.sort();
        report(
            "merge_remote (10 % of items edited elsewhere)",
            merges[2],
            None,
        );

        let t = median(9, || vault.lock_fingerprint_for_tests());
        report("sync fingerprint", t, None);

        let t = median(9, || vault.vault_summaries());
        report("kept list (vault_summaries)", t, None);

        let groups = groups_of(&vault, &open);
        let t = per_keystroke(|q| {
            std::hint::black_box(crate::multi_search(groups.clone(), q.to_string()));
        });
        report("multi_search per keystroke (all vaults)", t, Some(16.0));
        let notes: HashMap<String, String> =
            vault.items().into_iter().map(|i| (i.id, i.notes)).collect();
        let t = median(3, || crate::SearchIndex::new(groups.clone(), notes.clone()));
        report("SearchIndex::new (all vaults, once per change)", t, None);
        let (index, held) = retained_by(|| crate::SearchIndex::new(groups.clone(), notes.clone()));
        let (_, lists) = retained_by(|| groups.clone());
        println!(
            "{:<48} holds {:.1} MB ({:.1} MB of it the summaries)",
            "",
            held as f64 / MB,
            lists as f64 / MB
        );
        let t = per_keystroke(|q| {
            std::hint::black_box(index.search(q.to_string()));
        });
        report("SearchIndex::search per keystroke", t, Some(16.0));
        let t = per_keystroke(|q| {
            std::hint::black_box(index.search_positions(q.to_string()));
        });
        report("SearchIndex::search_positions per keystroke", t, Some(16.0));
        let summaries = vault.summaries();
        let t = per_keystroke(|q| {
            std::hint::black_box(crate::summaries_search_with_notes(
                summaries.clone(),
                notes.clone(),
                q.to_string(),
            ));
        });
        report("summaries_search_with_notes per keystroke", t, Some(16.0));
        let t = per_keystroke(|q| {
            std::hint::black_box(vault.search(q.to_string()));
        });
        report("Vault::search per keystroke", t, Some(16.0));

        let url = "https://accounts.github7.com/login".to_string();
        let t = median(9, || crate::multi_for_url(groups.clone(), url.clone()));
        report("multi_for_url (autofill, all vaults)", t, Some(16.0));
        let t = median(9, || index.for_url(url.clone()));
        report("SearchIndex::for_url (autofill, all vaults)", t, Some(16.0));
        let t = median(9, || vault.find_for_url(url.clone()));
        report("Vault::find_for_url", t, Some(16.0));
        let t = median(9, || {
            crate::summaries_for_url(summaries.clone(), url.clone())
        });
        report("summaries_for_url (soft-locked autofill)", t, Some(16.0));
        let t = median(9, || {
            crate::summaries_for_android_app(summaries.clone(), "com.github.android".into(), None)
        });
        report("summaries_for_android_app", t, Some(16.0));
        let t = median(5, || crate::KeptMatcher::new(summaries.clone()));
        report("KeptMatcher::new (once per soft lock)", t, None);
        let (matcher, held) = retained_by(|| crate::KeptMatcher::new(summaries.clone()));
        println!("{:<48} holds {:.2} MB", "", held as f64 / MB);
        let t = median(9, || matcher.for_url(url.clone()));
        report("KeptMatcher::for_url (soft-locked autofill)", t, Some(16.0));
        let t = median(9, || {
            matcher.for_android_app("com.github.android".into(), None)
        });
        report("KeptMatcher::for_android_app", t, Some(16.0));

        let id = vault
            .items()
            .into_iter()
            .find(|i| i.kind == ItemKind::Login)
            .unwrap()
            .id;
        let t = median(9, || {
            vault.lookalike_for_url("https://paypa1.com/signin".into(), id.clone())
        });
        report("lookalike_for_url (per page)", t, Some(5.0));
        let t = median(9, || {
            vault.lookalike_for_save("https://paypa1.com/signin".into())
        });
        report("lookalike_for_save (per page)", t, Some(5.0));

        let t = median(3, || crate::password_health(vault.clone()));
        report("password health report", t, None);

        let t = median(3, || {
            let mut by_prefix: HashMap<String, Vec<String>> = HashMap::new();
            for it in vault.items() {
                for p in std::iter::once(it.password.clone())
                    .chain(it.password_history.iter().map(|h| h.password.clone()))
                {
                    if !p.is_empty() {
                        let q = crate::hibp_prefix(p);
                        by_prefix.entry(q.prefix).or_default().push(q.suffix);
                    }
                }
            }
            by_prefix
        });
        report("breach check grouping (hash every password)", t, None);
    }
}

#[test]
#[ignore = "benchmark: run in an optimized build"]
fn perf_bench_memory_5000_items() {
    let (vault, held) = retained_by(|| demo_vault(5000, 3, fast_kdf()));
    let file = vault.serialize().unwrap();
    let key = vault.export_vault_key();
    drop(vault);
    let (opened, peak) =
        peak_of(|| Vault::unlock_with_key(file.clone(), key.clone(), "phone-1".into()).unwrap());
    let (_, kept) = retained_by(|| opened.vault_summaries());
    let (_, save_peak) = peak_of(|| opened.save_snapshot().unwrap());
    println!(
        "5 000 items: file {:.1} MB, built {:.1} MB, open peak {:.1} MB, kept list {:.1} MB, save peak {:.1} MB",
        file.len() as f64 / MB,
        held as f64 / MB,
        peak as f64 / MB,
        kept as f64 / MB,
        save_peak as f64 / MB
    );
}

// The kept work gives the same answers as doing it again.

const QUERIES: &[&str] = &[
    "",
    "g",
    "gi",
    "git",
    "gith",
    "github",
    "githbu",
    "gihtub 12",
    "kim",
    "kim.demo3",
    "example",
    "paypal",
    "paypa1",
    "accounts",
    "login",
    "#bank",
    "tag:music",
    "tag:music news",
    "1234",
    "4111",
    "kim demo",
    "ltd",
    "security question",
    "caf\u{e9}",
    "zzzz",
    "notes 7",
];

#[test]
fn search_index_answers_as_the_calls_without_it() {
    let home = demo_vault(400, 21, fast_kdf());
    let other = demo_vault(150, 22, fast_kdf());
    let groups = vec![home.vault_summaries(), other.vault_summaries()];
    let index = crate::SearchIndex::new(groups.clone(), HashMap::new());
    let flat: Vec<_> = groups.iter().flat_map(|g| g.summaries.iter()).collect();
    for q in QUERIES {
        let want = crate::multi_search(groups.clone(), q.to_string());
        assert_eq!(index.search(q.to_string()), want, "{q:?}");
        let by_place: Vec<_> = index
            .search_positions(q.to_string())
            .into_iter()
            .map(|p| flat[p as usize].clone())
            .collect();
        assert_eq!(
            by_place,
            want.into_iter().map(|r| r.summary).collect::<Vec<_>>(),
            "{q:?}"
        );
    }
    // With notes: as summaries_search_with_notes over one vault.
    let notes: HashMap<String, String> =
        home.items().into_iter().map(|i| (i.id, i.notes)).collect();
    let one = crate::SearchIndex::new(vec![home.vault_summaries()], notes.clone());
    for q in QUERIES {
        let want =
            crate::summaries_search_with_notes(home.summaries(), notes.clone(), q.to_string());
        let got: Vec<_> = one
            .search(q.to_string())
            .into_iter()
            .map(|r| r.summary)
            .collect();
        assert_eq!(got, want, "{q:?}");
    }
    let mut pages: Vec<String> = home
        .items()
        .iter()
        .flat_map(|i| i.urls.clone())
        .take(60)
        .collect();
    pages.extend(
        [
            "https://www.github7.com/x",
            "http://github7.com",
            "not a url",
            "https://co.uk",
        ]
        .map(String::from),
    );
    for page in &pages {
        assert_eq!(
            index.for_url(page.clone()),
            crate::multi_for_url(groups.clone(), page.clone()),
            "{page}"
        );
    }
    for package in ["com.github.android", "com.bank.android", "com.none.android"] {
        assert_eq!(
            index.for_android_app(package.into(), None),
            crate::multi_for_android_app(groups.clone(), package.into(), None)
        );
    }
}

#[test]
fn vault_search_is_the_same_with_kept_fields_and_follows_edits() {
    let vault = demo_vault(300, 23, fast_kdf());
    let fresh = |v: &Vault, q: &str| -> Vec<String> {
        // In the vault's own order (by id), so that ties come out alike.
        let mut items = v.items();
        items.sort_by(|a, b| a.id.cmp(&b.id));
        crate::search::rank_by(
            items.iter().collect::<Vec<_>>(),
            q,
            |q, i| crate::search::score(q, &crate::search::Doc::of_item(i)),
            |i| &i.title,
            |i| (i.favorite, v.usage(i.id.clone()).rank),
        )
        .into_iter()
        .map(|i| i.id.clone())
        .collect()
    };
    let ids = |items: Vec<Item>| -> Vec<String> { items.into_iter().map(|i| i.id).collect() };
    for q in QUERIES.iter().filter(|q| !q.is_empty()) {
        assert_eq!(ids(vault.search(q.to_string())), fresh(&vault, q), "{q:?}");
    }
    let mut item = vault.items().into_iter().next().unwrap();
    item.title = "Zebracorn".into();
    vault.upsert(item.clone()).unwrap();
    assert_eq!(ids(vault.search("zebracorn".into())), vec![item.id.clone()]);
    vault.delete(item.id.clone()).unwrap();
    assert!(vault.search("zebracorn".into()).is_empty());
}

#[test]
fn lookalike_checks_are_the_same_with_kept_sites_and_follow_edits() {
    let vault = demo_vault(300, 24, fast_kdf());
    let items = vault.items();
    let logins: Vec<&Item> = items.iter().filter(|i| i.kind == ItemKind::Login).collect();
    let mut pages: Vec<String> = logins
        .iter()
        .flat_map(|i| i.urls.iter())
        .take(40)
        .map(|u| {
            u.replacen("https://", "https://secure-", 1)
                .replace(".com", ".com.example.net")
        })
        .collect();
    for i in logins.iter().take(30) {
        let site = i.urls[0].clone();
        let host = url::Url::parse(&site)
            .unwrap()
            .host_str()
            .unwrap()
            .to_string();
        pages.push(format!("https://{}", host.replacen('o', "0", 1)));
        pages.push(format!("https://{}", host.replacen('e', "", 1)));
        pages.push(format!("https://example.org/{host}/login"));
        pages.push(site);
    }
    pages.extend(
        [
            "https://paypa1.com",
            "androidapp://com.github.androld",
            "nonsense",
        ]
        .map(String::from),
    );
    // Usage ranks decide between sites that tie.
    for (n, i) in logins.iter().enumerate().take(20) {
        for _ in 0..n {
            vault.record_use(i.id.clone(), 1_750_000_000_000).unwrap();
        }
    }
    let by_rank = || {
        let mut l = logins.clone();
        l.sort_by_key(|i| std::cmp::Reverse(vault.usage(i.id.clone()).rank));
        l.iter()
            .flat_map(|i| crate::login_sites(&i.urls, &i.android_apps))
            .collect::<Vec<_>>()
    };
    let known: Vec<String> = items
        .iter()
        .flat_map(|i| crate::login_sites(&i.urls, &i.android_apps))
        .collect();
    let mut found = 0;
    for page in &pages {
        let sites = by_rank();
        let want = crate::LookalikeCheck::new(page, std::iter::empty())
            .and_then(|c| c.against(sites.iter().map(String::as_str)));
        found += usize::from(want.is_some());
        assert_eq!(vault.lookalike_for_save(page.clone()), want, "{page}");
        for i in logins.iter().take(5) {
            let want =
                crate::LookalikeCheck::new(page, known.iter().map(String::as_str)).and_then(|c| {
                    c.against(
                        crate::login_sites(&i.urls, &i.android_apps)
                            .iter()
                            .map(String::as_str),
                    )
                });
            assert_eq!(
                vault.lookalike_for_url(page.clone(), i.id.clone()),
                want,
                "{page}"
            );
        }
    }
    assert!(found > 20, "only {found} lookalikes among the test pages");
    // A new login for the page's site: the page is the user's own site now.
    let page = "https://zebracorn-shop.com";
    let mut item = logins[0].clone();
    item.urls = vec!["https://zebracorn-sh0p.com".into()];
    vault.upsert(item.clone()).unwrap();
    assert!(vault.lookalike_for_save(page.into()).is_some());
    let new = Item {
        urls: vec![page.into()],
        title: "New".into(),
        ..Default::default()
    };
    vault.upsert(new).unwrap();
    assert!(vault.lookalike_for_save(page.into()).is_none());
}

/// The quick "not the same site" check before the Public Suffix List misses no same-site match.
#[test]
fn url_match_shortcut_agrees_with_the_suffix_list() {
    use crate::matching::{parse_loose, registrable_domain_of_host, url_match, MatchQuality};
    let hosts = [
        "example.com",
        "www.example.com",
        "a.b.example.com",
        "example.co.uk",
        "shop.example.co.uk",
        "other.co.uk",
        "co.uk",
        "github.io",
        "kim.github.io",
        "lee.github.io",
        "localhost",
        "127.0.0.1",
        "10.0.0.1",
        "[::1]",
        "example.com.",
        "xn--bcher-kva.de",
        "b\u{fc}cher.de",
        "a.de",
        "foo.blogspot.com",
        "bar.blogspot.com",
        "blogspot.com",
        "s3.amazonaws.com",
        "x.s3.amazonaws.com",
        "WWW.Example.COM",
        "sub.xn--bcher-kva.de",
    ];
    let mut domain_matches = 0;
    for a in hosts {
        for b in hosts {
            for (sa, sb) in [("https", "https"), ("http", "https"), ("https", "http")] {
                let (stored, page) = (format!("{sa}://{a}/login"), format!("{sb}://{b}/login/x"));
                let p = parse_loose(&page).unwrap();
                let s = parse_loose(&stored).unwrap();
                let q = url_match(&stored, &p);
                let (sh, ph) = (
                    s.host_str().unwrap().to_string(),
                    p.host_str().unwrap().to_string(),
                );
                let downgrade = sa == "https"
                    && sb == "http"
                    && b != "localhost"
                    && !b.starts_with("127.")
                    && b != "[::1]";
                if sh != ph && !downgrade {
                    let same = matches!(
                        (registrable_domain_of_host(&sh), registrable_domain_of_host(&ph)),
                        (Some(x), Some(y)) if x == y && sh.contains('.')
                    );
                    assert_eq!(q == MatchQuality::Domain, same, "{stored} on {page}");
                    domain_matches += usize::from(same);
                }
            }
        }
    }
    assert!(domain_matches > 10);
}

/// Ruling items out by the letters they lack changes no search result.
#[test]
fn search_shortcuts_change_no_result() {
    let vault = demo_vault(400, 25, fast_kdf());
    let items = vault.items();
    let mut queries: Vec<String> = QUERIES.iter().map(|q| q.to_string()).collect();
    queries.extend(
        [
            "kim.demo",
            "kim-demo3",
            "accounts.git",
            "gtihub",
            "githubb",
            "musci",
            "hotle 1",
            "ltd.",
            "a",
            "4",
            "-",
            "x.y",
        ]
        .map(String::from),
    );
    // Titles and sites with a letter dropped, doubled or swapped, and in pieces.
    for i in items.iter().take(40) {
        let t = crate::search::normalize(&i.title);
        let w = t.split_whitespace().next().unwrap_or("").to_string();
        if w.len() > 3 {
            queries.push(w[1..].to_string());
            queries.push(format!("{}{}", &w[..2], &w[1..]));
            queries.push(format!("{}{}{}", &w[1..2], &w[..1], &w[2..]));
            queries.push(format!("{} {}", &w[..3], i.username.get(..4).unwrap_or("")));
        }
    }
    for q in &queries {
        let fast = crate::items_search(items.clone(), q.clone());
        let slow =
            crate::search::without_shortcuts(|| crate::items_search(items.clone(), q.clone()));
        assert_eq!(fast, slow, "{q:?}");
    }
}

/// Writes the benchmarks' demo vault (5 000 items, default Argon2id parameters, master password
/// `demo master password`) to `$PASS_PERF_OUT/demo-5000.vault`, for the browser extension's
/// WebAssembly timings.
#[test]
#[ignore = "writes a benchmark fixture: set PASS_PERF_OUT"]
fn perf_write_wasm_fixture() {
    let Ok(dir) = std::env::var("PASS_PERF_OUT") else {
        return;
    };
    let vault = demo_vault(5000, 2, KdfParams::default());
    let path = std::path::Path::new(&dir).join("demo-5000.vault");
    std::fs::write(&path, vault.serialize().unwrap()).unwrap();
    println!("wrote {}", path.display());
}

/// The soft-locked list's matcher answers as the calls over the whole list.
#[test]
fn kept_matcher_answers_as_the_calls_over_the_list() {
    let vault = demo_vault(500, 26, fast_kdf());
    for (n, i) in vault.items().iter().enumerate().take(30) {
        for _ in 0..n % 4 {
            vault.record_use(i.id.clone(), 1_750_000_000_000).unwrap();
        }
    }
    let mut kept = vault.summaries();
    // Entries the apps keep too: app links, a bare host, local addresses, http.
    kept[0].urls.push("androidapp://com.Example.App".into());
    kept[1].urls = vec!["github7.com".into(), "http://192.168.1.1".into()];
    kept[2].urls = vec!["http://localhost:8080/login".into()];
    let matcher = crate::KeptMatcher::new(kept.clone());
    let at = |places: Vec<u32>| -> Vec<String> {
        places
            .into_iter()
            .map(|p| kept[p as usize].id.clone())
            .collect()
    };
    let ids =
        |list: Vec<crate::ItemSummary>| -> Vec<String> { list.into_iter().map(|s| s.id).collect() };
    let mut pages: Vec<String> = kept.iter().flat_map(|s| s.urls.clone()).take(80).collect();
    pages.extend(
        [
            "https://www.github7.com/x",
            "http://github7.com",
            "http://localhost:8080/",
            "https://localhost:8080/",
            "http://192.168.1.1/admin",
            "not a url",
            "androidapp://com.example.app",
        ]
        .map(String::from),
    );
    for page in &pages {
        assert_eq!(
            at(matcher.for_url(page.clone())),
            ids(crate::summaries_for_url(kept.clone(), page.clone())),
            "{page}"
        );
    }
    let mut apps: Vec<(String, Option<String>)> = kept
        .iter()
        .flat_map(|s| s.android_apps.iter())
        .take(10)
        .map(|a| (a.package.clone(), a.cert_sha256.clone()))
        .collect();
    apps.push(("com.Example.App".into(), None));
    apps.push(("com.example.app".into(), Some("AB:CD".into())));
    apps.push(("com.github.android".into(), Some("00".into())));
    for (package, cert) in apps {
        assert_eq!(
            at(matcher.for_android_app(package.clone(), cert.clone())),
            ids(crate::summaries_for_android_app(
                kept.clone(),
                package.clone(),
                cert
            )),
            "{package}"
        );
    }
    let rps: Vec<String> = kept
        .iter()
        .flat_map(|s| s.passkeys.iter())
        .take(10)
        .map(|p| p.rp_id.to_uppercase())
        .collect();
    for rp in rps {
        assert_eq!(
            at(matcher.with_passkeys(rp.clone())),
            ids(crate::summaries_with_passkeys(kept.clone(), rp.clone()))
        );
    }
}

/// Entries read once for page matching ([`crate::matching::MatchUrl`]) match as the entries do.
#[test]
fn match_urls_read_once_agree_with_the_entries() {
    use crate::matching::{parse_loose, tier_of, url_suggestion_tier, MatchPage, MatchUrl};
    use crate::model::{UrlMatch, UrlRule};
    let hosts = [
        "example.com",
        "www.example.com",
        "a.b.example.com",
        "example.co.uk",
        "shop.example.co.uk",
        "co.uk",
        "kim.github.io",
        "lee.github.io",
        "localhost",
        "127.0.0.1",
        "10.0.0.1",
        "[::1]",
        "example.com.",
        "xn--bcher-kva.de",
        "b\u{fc}cher.de",
        "WWW.Example.COM",
        "intranet",
    ];
    let schemes = ["https://", "http://", "", "ftp://", "androidapp://"];
    let rules = [UrlMatch::Subdomains, UrlMatch::Host, UrlMatch::Never];
    for a in hosts {
        for b in hosts {
            for sa in schemes {
                for sb in ["https://", "http://"] {
                    for (stored_port, page_port) in [(":8443", ""), (":8443", ":8443"), ("", "")] {
                        let stored = format!("{sa}{a}{stored_port}/login");
                        let page = parse_loose(&format!("{sb}{b}{page_port}/login/x")).unwrap();
                        for rule in rules {
                            let ruled = [UrlRule {
                                url: stored.clone(),
                                rule,
                            }];
                            let once: Vec<MatchUrl> =
                                MatchUrl::parse(&stored, rule).into_iter().collect();
                            assert_eq!(
                                tier_of(&once, &MatchPage::of(&page)),
                                url_suggestion_tier(std::slice::from_ref(&stored), &ruled, &page),
                                "{stored} ({rule:?}) on {page}"
                            );
                        }
                    }
                }
            }
        }
    }
}
