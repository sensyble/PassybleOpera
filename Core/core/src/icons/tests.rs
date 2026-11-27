//! Icon resolution against an in-process HTTP server that answers for any host name, routing on
//! the `Host` header.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};

use image::{ImageFormat, RgbaImage};

use super::cache::{self, CachedSiteIcon};
use super::*;

#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn ok(content_type: &str, body: impl Into<Vec<u8>>) -> Reply {
    Reply {
        status: 200,
        headers: vec![("Content-Type".into(), content_type.into())],
        body: body.into(),
    }
}

fn redirect(to: &str) -> Reply {
    Reply {
        status: 302,
        headers: vec![("Location".into(), to.into())],
        body: Vec::new(),
    }
}

fn html(head: &str) -> Reply {
    ok(
        "text/html; charset=utf-8",
        format!("<!doctype html><html><head>{head}</head><body>hi</body></html>"),
    )
}

/// A `side`×`side` opaque PNG (or another format) whose top-left pixel is `tag`, so tests can
/// tell which source was picked.
fn image(side: u32, tag: u8, format: ImageFormat) -> Vec<u8> {
    let img = RgbaImage::from_fn(side, side, |x, y| {
        if x == 0 && y == 0 {
            image::Rgba([tag, tag, tag, 255])
        } else {
            image::Rgba([10, 120, 200, 255])
        }
    });
    let mut out = Vec::new();
    let img = image::DynamicImage::ImageRgba8(img);
    match format {
        ImageFormat::Jpeg => img.to_rgb8().write_to(&mut Cursor::new(&mut out), format),
        _ => img.write_to(&mut Cursor::new(&mut out), format),
    }
    .unwrap();
    out
}

fn png(side: u32, tag: u8) -> Reply {
    ok("image/png", image(side, tag, ImageFormat::Png))
}

/// (host, path, headers) of one request.
type Request = (String, String, Vec<(String, String)>);

#[derive(Default)]
struct Site {
    routes: HashMap<(String, String), Reply>,
    /// (host, path, headers) of every request.
    log: Vec<Request>,
}

struct Server {
    site: Arc<Mutex<Site>>,
    addr: SocketAddr,
}

impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let site = Arc::new(Mutex::new(Site::default()));
        let shared = site.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let mut headers = Vec::new();
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).is_err() || h.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                    }
                }
                let host = headers
                    .iter()
                    .find(|(k, _)| k == "host")
                    .map(|(_, v)| v.split(':').next().unwrap_or_default().to_string())
                    .unwrap_or_default();
                let reply = {
                    let mut site = shared.lock().unwrap();
                    site.log.push((host.clone(), path.clone(), headers));
                    site.routes.get(&(host, path)).cloned()
                }
                .unwrap_or(Reply {
                    status: 404,
                    headers: vec![("Content-Type".into(), "text/plain".into())],
                    body: b"not found".to_vec(),
                });
                let mut out = format!("HTTP/1.1 {} X\r\n", reply.status);
                for (k, v) in &reply.headers {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str(&format!(
                    "Content-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.body.len()
                ));
                let _ = stream.write_all(out.as_bytes());
                let _ = stream.write_all(&reply.body);
            }
        });
        Self { site, addr }
    }

    fn route(&self, host: &str, path: &str, reply: Reply) -> &Self {
        self.site
            .lock()
            .unwrap()
            .routes
            .insert((host.into(), path.into()), reply);
        self
    }

    fn options(&self) -> Options {
        Options {
            scheme: "http",
            resolve_to: Some(self.addr),
        }
    }

    fn fetch(&self, domain: &str) -> Result<SiteIcon> {
        fetch_with(domain, &self.options())
    }

    fn paths(&self) -> Vec<String> {
        self.site
            .lock()
            .unwrap()
            .log
            .iter()
            .map(|(h, p, _)| format!("{h}{p}"))
            .collect()
    }
}

#[test]
fn manifest_192_beats_512_and_other_sources() {
    let s = Server::start();
    s.route(
        "example.com",
        "/",
        html(
            r#"<link rel="manifest" href="/app/manifest.webmanifest">
                <link rel="apple-touch-icon" href="/apple.png">
                <link rel="icon" sizes="256x256" href="/icon256.png">"#,
        ),
    )
    .route(
        "example.com",
        "/app/manifest.webmanifest",
        ok(
            "application/manifest+json",
            r#"{"icons":[
                {"src":"i512.png","sizes":"512x512","type":"image/png"},
                {"src":"mono.png","sizes":"192x192","purpose":"monochrome"},
                {"src":"i.svg","sizes":"192x192","type":"image/svg+xml"},
                {"src":"i192.png","sizes":"192x192","type":"image/png"}]}"#,
        ),
    )
    .route("example.com", "/app/i192.png", png(192, 250))
    .route("example.com", "/app/i512.png", png(512, 5));
    let icon = s.fetch("example.com").unwrap();
    assert_eq!(
        (icon.width, icon.height, icon.mime.as_str()),
        (128, 128, "image/png")
    );
    assert!(
        icon.source_url.ends_with("/app/i192.png"),
        "{}",
        icon.source_url
    );
    assert_eq!(
        s.paths(),
        [
            "example.com/",
            "example.com/app/manifest.webmanifest",
            "example.com/app/i192.png"
        ]
    );
}

#[test]
fn requests_are_anonymous() {
    let s = Server::start();
    s.route("example.com", "/favicon.ico", png(32, 1));
    s.fetch("example.com").unwrap();
    let site = s.site.lock().unwrap();
    for (_, _, headers) in &site.log {
        let get = |k: &str| {
            headers
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("user-agent"), Some(USER_AGENT));
        assert_eq!(get("cookie"), None);
        assert_eq!(get("authorization"), None);
        assert_eq!(get("referer"), None);
    }
}

#[test]
fn falls_back_through_manifest_512_apple_icons_and_favicon() {
    let s = Server::start();
    s.route(
        "example.com",
        "/",
        html(r#"<link rel="apple-touch-icon" href="/apple.png">"#),
    )
    .route(
        "example.com",
        "/manifest.json",
        ok(
            "application/json",
            r#"{"icons":[{"src":"/m512.png","sizes":"512x512"}]}"#,
        ),
    )
    .route("example.com", "/m512.png", png(512, 7))
    .route("example.com", "/apple.png", png(180, 200));
    assert!(s
        .fetch("example.com")
        .unwrap()
        .source_url
        .ends_with("/m512.png"));

    let s = Server::start();
    s.route(
        "example.com",
        "/",
        html(
            r#"<link rel="apple-touch-icon" sizes="120x120" href="/a120.png">
                <link rel="apple-touch-icon" sizes="180x180" href="/a180.png">
                <link rel="icon" sizes="192x192" href="/i192.png">"#,
        ),
    )
    .route("example.com", "/a120.png", png(120, 1))
    .route("example.com", "/a180.png", png(180, 2))
    .route("example.com", "/i192.png", png(192, 3));
    let icon = s.fetch("example.com").unwrap();
    assert!(icon.source_url.ends_with("/a180.png"));
    assert!(s
        .paths()
        .contains(&"example.com/site.webmanifest".to_string()));

    // Large link icons before the conventional apple path, small ones after it.
    let s = Server::start();
    s.route(
        "example.com",
        "/",
        html(
            r#"<link rel="icon" sizes="16x16" href="/i16.png">
                <link rel="icon" sizes="32x32" href="/i32.png">"#,
        ),
    )
    .route("example.com", "/apple-touch-icon.png", png(180, 4))
    .route("example.com", "/i32.png", png(32, 5))
    .route("example.com", "/i16.png", png(16, 6));
    assert!(s
        .fetch("example.com")
        .unwrap()
        .source_url
        .ends_with("/apple-touch-icon.png"));
    let s2 = Server::start();
    s2.route(
        "example.com",
        "/",
        html(
            r#"<link rel="icon" sizes="16x16" href="/i16.png">
                <link rel="icon" sizes="32x32" href="/i32.png">"#,
        ),
    )
    .route("example.com", "/i32.png", png(32, 5))
    .route("example.com", "/i16.png", png(16, 6));
    let icon = s2.fetch("example.com").unwrap();
    assert!(icon.source_url.ends_with("/i32.png"));
    assert_eq!(
        (icon.width, icon.height),
        (32, 32),
        "small icons are not enlarged"
    );

    // Only a favicon.ico (the decoder's best frame).
    let s = Server::start();
    s.route("example.com", "/", html("")).route(
        "example.com",
        "/favicon.ico",
        ok("image/x-icon", image(48, 9, ImageFormat::Ico)),
    );
    let icon = s.fetch("example.com").unwrap();
    assert!(icon.source_url.ends_with("/favicon.ico"));
    assert_eq!(icon.width, 48);
}

#[test]
fn exact_host_first_then_registrable_domain() {
    let s = Server::start();
    s.route("accounts.example.com", "/", html(""))
        .route(
            "example.com",
            "/",
            html(r#"<link rel="icon" href="/x.png">"#),
        )
        .route("example.com", "/x.png", png(64, 1));
    let icon = s.fetch("accounts.example.com").unwrap();
    assert!(icon.source_url.contains("://example.com/x.png"));
    let paths = s.paths();
    assert_eq!(paths[0], "accounts.example.com/");
    assert!(paths
        .iter()
        .any(|p| p == "accounts.example.com/favicon.ico"));

    let s = Server::start();
    s.route("mail.example.com", "/favicon.ico", png(32, 1))
        .route("example.com", "/favicon.ico", png(32, 2));
    assert!(s
        .fetch("mail.example.com")
        .unwrap()
        .source_url
        .contains("mail.example.com"));
    assert!(!s.paths().iter().any(|p| p.starts_with("example.com")));
}

#[test]
fn follows_a_few_redirects_and_resolves_relative_to_the_final_page() {
    let s = Server::start();
    s.route("example.com", "/", redirect("http://www.example.com/home/"))
        .route(
            "www.example.com",
            "/home/",
            html(r#"<link rel="icon" href="icon.png">"#),
        )
        .route(
            "www.example.com",
            "/home/icon.png",
            redirect("/static/icon.png"),
        )
        .route("www.example.com", "/static/icon.png", png(64, 1));
    let icon = s.fetch("example.com").unwrap();
    assert_eq!(icon.source_url, "http://www.example.com/static/icon.png");

    let s = Server::start();
    s.route(
        "example.com",
        "/",
        html(r#"<base href="http://cdn.example.net/assets/"><link rel="icon" href="i.png">"#),
    )
    .route("cdn.example.net", "/assets/i.png", png(64, 1));
    assert!(s
        .fetch("example.com")
        .unwrap()
        .source_url
        .starts_with("http://cdn.example.net/"));

    let s = Server::start();
    s.route("example.com", "/", html(r#"<link rel="icon" href="/r1">"#))
        .route("example.com", "/r1", redirect("/r2"))
        .route("example.com", "/r2", redirect("/r3"))
        .route("example.com", "/r3", redirect("/r4"))
        .route("example.com", "/r4", redirect("/icon.png"))
        .route("example.com", "/icon.png", png(64, 1));
    let err = s.fetch("example.com");
    assert!(matches!(err, Err(PassError::NotFound(_))), "{err:?}");
    assert!(!s.paths().contains(&"example.com/icon.png".to_string()));
}

#[test]
fn redirects_to_another_scheme_are_refused() {
    // The tests run on http, so a hop to https is the "other scheme" here; in production the
    // allowed scheme is https and a hop to http is refused the same way.
    let s = Server::start();
    s.route(
        "example.com",
        "/",
        html(r#"<link rel="icon" href="/i.png">"#),
    )
    .route(
        "example.com",
        "/i.png",
        redirect("https://example.com/i.png"),
    )
    .route(
        "example.com",
        "/favicon.ico",
        redirect("ftp://example.com/favicon.ico"),
    );
    assert!(matches!(
        s.fetch("example.com"),
        Err(PassError::NotFound(_))
    ));

    let production = Options::default();
    let fetcher = Fetcher::new(&production);
    assert!(fetcher.allowed(&Url::parse("https://example.com/i.png").unwrap()));
    for refused in [
        "http://example.com/i.png",
        "https://user:pw@example.com/i.png",
        "https://127.0.0.1/i.png",
        "https://[::1]/i.png",
        "https://localhost/i.png",
        "https://router.local/i.png",
        "https://nas.internal/i.png",
        "file:///C:/Windows/win.ini",
    ] {
        assert!(!fetcher.allowed(&Url::parse(refused).unwrap()), "{refused}");
    }
}

#[test]
fn size_caps() {
    let s = Server::start();
    // A 600 KB "icon" is refused; the favicon is used instead.
    let mut huge = image(64, 1, ImageFormat::Png);
    huge.resize(600 * 1024, 0);
    s.route(
        "example.com",
        "/",
        html(r#"<link rel="icon" sizes="512x512" href="/huge.png">"#),
    )
    .route("example.com", "/huge.png", ok("image/png", huge))
    .route("example.com", "/favicon.ico", png(32, 2));
    assert!(s
        .fetch("example.com")
        .unwrap()
        .source_url
        .ends_with("/favicon.ico"));

    // HTML is read up to 256 KB: a link after that is not seen.
    let s = Server::start();
    let mut page = String::from("<html><head><title>x</title>");
    page.push_str(&"<meta name=x content=y>".repeat(300 * 1024 / 23));
    page.push_str(r#"<link rel="icon" href="/late.png"></head>"#);
    s.route("example.com", "/", ok("text/html", page)).route(
        "example.com",
        "/late.png",
        png(64, 1),
    );
    assert!(matches!(
        s.fetch("example.com"),
        Err(PassError::NotFound(_))
    ));
    assert!(!s.paths().contains(&"example.com/late.png".to_string()));
}

#[test]
fn bad_images_are_skipped() {
    let s = Server::start();
    let mut truncated = image(64, 1, ImageFormat::Png);
    truncated.truncate(truncated.len() / 2);
    s.route(
        "example.com",
        "/",
        html(
            r#"<link rel="icon" sizes="256x256" href="/html.png">
                <link rel="icon" sizes="200x200" href="/svg.png">
                <link rel="icon" sizes="160x160" href="/broken.png">
                <link rel="icon" sizes="150x150" href="/tiny.png">
                <link rel="icon" sizes="140x140" href="/clear.png">
                <link rel="icon" type="image/svg+xml" href="/vector.svg">"#,
        ),
    )
    .route("example.com", "/html.png", html("not an image"))
    .route(
        "example.com",
        "/svg.png",
        ok("image/png", r#"<svg xmlns="http://www.w3.org/2000/svg"/>"#),
    )
    .route("example.com", "/broken.png", ok("image/png", truncated))
    .route("example.com", "/tiny.png", png(8, 1))
    .route(
        "example.com",
        "/clear.png",
        ok("image/png", {
            let mut out = Vec::new();
            RgbaImage::new(64, 64)
                .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
                .unwrap();
            out
        }),
    )
    .route(
        "example.com",
        "/apple-touch-icon.png",
        ok("image/jpeg", image(180, 200, ImageFormat::Jpeg)),
    );
    let icon = s.fetch("example.com").unwrap();
    assert!(
        icon.source_url.ends_with("/apple-touch-icon.png"),
        "{}",
        icon.source_url
    );
    assert!(!s.paths().contains(&"example.com/vector.svg".to_string()));
}

#[test]
fn webp_gif_and_data_urls() {
    let s = Server::start();
    s.route(
        "example.com",
        "/",
        html(r#"<link rel="icon" href="/i.webp">"#),
    )
    .route(
        "example.com",
        "/i.webp",
        ok("image/webp", image(64, 1, ImageFormat::WebP)),
    );
    assert_eq!(s.fetch("example.com").unwrap().width, 64);

    let s = Server::start();
    s.route(
        "example.com",
        "/",
        html(r#"<link rel="icon" href="/i.gif">"#),
    )
    .route(
        "example.com",
        "/i.gif",
        ok("image/gif", image(64, 1, ImageFormat::Gif)),
    );
    assert_eq!(s.fetch("example.com").unwrap().width, 64);

    let s = Server::start();
    let data = base64::engine::general_purpose::STANDARD.encode(image(40, 1, ImageFormat::Png));
    s.route(
        "example.com",
        "/",
        html(&format!(
            r#"<link rel="icon" href="data:image/png;base64,{data}">"#
        )),
    );
    let icon = s.fetch("example.com").unwrap();
    assert_eq!(icon.width, 40);
    assert_eq!(
        s.paths(),
        [
            "example.com/",
            "example.com/manifest.json",
            "example.com/site.webmanifest",
            "example.com/apple-touch-icon.png"
        ]
    );
}

#[test]
fn unreachable_vs_no_icon() {
    let s = Server::start();
    assert!(matches!(
        s.fetch("example.com"),
        Err(PassError::NotFound(_))
    ));
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let options = Options {
        scheme: "http",
        resolve_to: Some(closed),
    };
    let started = Instant::now();
    assert!(matches!(
        fetch_with("example.com", &options),
        Err(PassError::Network(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn domains_and_addresses() {
    let d = |s: &str| site_icon_domain(s.into());
    assert_eq!(
        d("https://www.GitHub.com/login").as_deref(),
        Some("github.com")
    );
    assert_eq!(
        d("accounts.google.com").as_deref(),
        Some("accounts.google.com")
    );
    assert_eq!(
        d("https://shop.example.co.uk:8443/x").as_deref(),
        Some("shop.example.co.uk")
    );
    for none in [
        "android://com.example.app",
        "https://192.168.1.1/",
        "http://[::1]/",
        "localhost",
        "http://router.local",
        "nas.internal",
        "co.uk",
        "intranet",
        "something.onion",
        "foo.notarealtld",
        "",
    ] {
        assert_eq!(d(none), None, "{none}");
    }
    assert!(matches!(
        fetch_site_icon("127.0.0.1".into()),
        Err(PassError::InvalidInput(_))
    ));

    for public in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
        assert!(is_public_ip(public.parse().unwrap()), "{public}");
    }
    for private in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "fd00::1",
        "fe80::1",
        "::ffff:192.168.0.1",
    ] {
        assert!(!is_public_ip(private.parse().unwrap()), "{private}");
    }
    let resolver = PublicResolver { resolve_to: None };
    assert!(ureq::Resolver::resolve(&resolver, "localhost:443").is_err());
}

#[test]
fn cache_round_trip_and_freshness() {
    let dir = std::env::temp_dir().join(format!("pass-icons-{:x}", rand::random::<u64>()));
    let dir_s = dir.to_string_lossy().to_string();
    let s = Server::start();
    s.route("example.com", "/favicon.ico", png(32, 1));
    let t0 = 1_700_000_000_000;

    assert_eq!(
        cache::site_icon_cache_read(dir_s.clone(), "example.com".into()),
        None
    );
    let png = cache::refresh_with(&dir_s, "example.com", &s.options(), t0)
        .unwrap()
        .unwrap();
    let name = cache::site_icon_cache_file_name("example.com".into());
    assert_eq!(name.len(), 64 + ".icon".len());
    assert!(!name.contains("example"));
    assert!(dir.join(&name).exists());

    let read = |now: i64, domain: &str| cache::read_at(&dir_s, domain, now);
    assert_eq!(
        read(t0 + 1000, "example.com"),
        Some(CachedSiteIcon {
            png: Some(png.clone()),
            fetched_at_ms: t0,
            needs_refresh: false
        })
    );
    assert!(
        read(t0 + cache::ICON_MAX_AGE_MS, "example.com")
            .unwrap()
            .needs_refresh
    );
    assert!(
        read(t0 - 2 * 86_400_000, "example.com")
            .unwrap()
            .needs_refresh
    );

    // The site loses its icon / goes down: the cached one is kept, retried in a day.
    s.site.lock().unwrap().routes.clear();
    let t1 = t0 + cache::ICON_MAX_AGE_MS;
    assert_eq!(
        cache::refresh_with(&dir_s, "example.com", &s.options(), t1).unwrap(),
        Some(png.clone())
    );
    let kept = read(t1, "example.com").unwrap();
    assert_eq!(kept.png, Some(png));
    assert!(!kept.needs_refresh);
    assert!(
        read(t1 + cache::FAILED_MAX_AGE_MS, "example.com")
            .unwrap()
            .needs_refresh
    );

    // A site without an icon: negative entry for 7 days.
    assert_eq!(
        cache::refresh_with(&dir_s, "none.example.com", &s.options(), t0).unwrap(),
        None
    );
    let none = read(t0 + 1, "none.example.com").unwrap();
    assert_eq!((none.png, none.needs_refresh), (None, false));
    assert!(
        !read(t0 + cache::NONE_MAX_AGE_MS - 1, "none.example.com")
            .unwrap()
            .needs_refresh
    );
    assert!(
        read(t0 + cache::NONE_MAX_AGE_MS, "none.example.com")
            .unwrap()
            .needs_refresh
    );

    // Unreachable: retried after a day.
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let down = Options {
        scheme: "http",
        resolve_to: Some(closed),
    };
    assert_eq!(
        cache::refresh_with(&dir_s, "down.example.com", &down, t0).unwrap(),
        None
    );
    assert!(!read(t0 + 1, "down.example.com").unwrap().needs_refresh);
    assert!(
        read(t0 + cache::FAILED_MAX_AGE_MS, "down.example.com")
            .unwrap()
            .needs_refresh
    );

    std::fs::write(
        dir.join(cache::site_icon_cache_file_name("junk.example.com".into())),
        b"xx",
    )
    .unwrap();
    assert_eq!(read(t0, "junk.example.com"), None);
    assert!(
        cache::site_icon_cache_refresh(dir_s.clone(), "https://www.example.com/".into()).is_err()
    );

    std::fs::write(dir.join("keep.txt"), b"not ours").unwrap();
    assert_eq!(cache::site_icon_cache_clear(dir_s.clone()).unwrap(), 4);
    assert!(dir.join("keep.txt").exists());
    assert_eq!(
        cache::site_icon_cache_read(dir_s.clone(), "example.com".into()),
        None
    );
    assert_eq!(
        cache::site_icon_cache_clear(dir.join("missing").to_string_lossy().into()).unwrap(),
        0
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Real sites over the internet: `cargo test -p pass-core --lib icons::tests::live -- --ignored --nocapture`.
#[test]
#[ignore = "needs the internet"]
fn live() {
    for domain in [
        "github.com",
        "accounts.google.com",
        "wikipedia.org",
        "bbc.co.uk",
        "news.ycombinator.com",
    ] {
        let started = Instant::now();
        match fetch_site_icon(domain.into()) {
            Ok(icon) => println!(
                "{domain}: {}x{} {} bytes from {} in {:?}",
                icon.width,
                icon.height,
                icon.bytes.len(),
                icon.source_url,
                started.elapsed()
            ),
            Err(e) => println!("{domain}: {e} in {:?}", started.elapsed()),
        }
    }
}
