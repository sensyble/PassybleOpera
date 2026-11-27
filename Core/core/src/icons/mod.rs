//! Website icons for item avatars: [`fetch_site_icon`] finds a site's icon and returns a small PNG,
//! [`cache`] keeps one file per domain. Only the host name leaves the device, over anonymous HTTPS
//! GETs. IP literals and local names are refused and private DNS answers dropped, so a public name
//! can't point the fetch into the local network.

pub mod cache;
mod html;
#[cfg(test)]
mod tests;

use std::io::{self, Cursor, Read};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use base64::Engine as _;
use image::{ImageFormat, ImageReader, Limits};
use url::Url;

use crate::matching::{parse_loose, registrable_domain_of_host};
use crate::{PassError, Result};
use html::{parse_head, parse_sizes, Head, Link};

/// Sent with every request, so sites can tell (and block) icon fetches.
pub const USER_AGENT: &str = "Passyble-icon/1";
/// The stored icon's largest side, in pixels.
pub const ICON_SIDE: u32 = 128;
/// Redirects followed per request.
pub const MAX_REDIRECTS: usize = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Per request, connect to last byte.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// For one domain, all requests together.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(20);
/// HTML beyond this is not read (the `<head>` comes first).
const HTML_CAP: usize = 256 * 1024;
const MANIFEST_CAP: usize = 128 * 1024;
const ICON_CAP: usize = 512 * 1024;
/// Smaller images (tracking pixels, broken files) don't count as icons.
const MIN_SIDE: u32 = 16;
/// Decoder limits: icons are small, anything near this is hostile.
const MAX_DECODE_SIDE: u32 = 4096;
/// Requests per domain, so a site full of broken links can't keep us busy.
const MAX_REQUESTS: usize = 16;

/// A website's icon, ready to store and show: always a PNG.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SiteIcon {
    /// PNG, at most [`ICON_SIDE`] px on its longer side (smaller sources are not enlarged).
    pub bytes: Vec<u8>,
    /// Always `image/png`.
    pub mime: String,
    pub width: u32,
    pub height: u32,
    /// Where the image came from (after redirects), for diagnostics.
    pub source_url: String,
}

/// The host whose icon an item shows, from one of its URLs: lower-case, without `www.` and the
/// port, or `None` when there is nothing to fetch (an app link, an IP address, `localhost`, an
/// intranet name or another host under no known public suffix). Use it as the cache key.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn site_icon_domain(url_or_host: String) -> Option<String> {
    let url = parse_loose(&url_or_host)?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
    public_host(&host).then_some(host)
}

/// Fetches `domain`'s icon (web app manifest, apple-touch-icon, `<link rel="icon">`, then
/// `/favicon.ico`). `domain` is a host or URL, normalised with [`site_icon_domain`]. Blocks for up
/// to about 20 seconds; call it off the UI thread.
///
/// Errors: `InvalidInput` for a host that isn't a public name, `NotFound` when the site answered
/// but has no usable icon, `Network` when it couldn't be reached at all.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn fetch_site_icon(domain: String) -> Result<SiteIcon> {
    let domain = site_icon_domain(domain)
        .ok_or_else(|| PassError::InvalidInput("not a public website host".into()))?;
    fetch_with(&domain, &Options::default())
}

/// How [`fetch_with`] connects. Production: HTTPS and public addresses only. Tests point every
/// host name at a local plain-HTTP server instead.
#[derive(Clone, Debug)]
pub(crate) struct Options {
    scheme: &'static str,
    resolve_to: Option<SocketAddr>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            scheme: "https",
            resolve_to: None,
        }
    }
}

/// Resolves names normally but drops addresses that aren't globally routable (DNS rebinding,
/// names that point at the LAN). With `resolve_to` (tests), every name resolves to it.
struct PublicResolver {
    resolve_to: Option<SocketAddr>,
}

impl ureq::Resolver for PublicResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        if let Some(addr) = self.resolve_to {
            return Ok(vec![addr]);
        }
        let addrs: Vec<SocketAddr> = netloc
            .to_socket_addrs()?
            .filter(|a| is_public_ip(a.ip()))
            .collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the name resolves to no public address",
            ));
        }
        Ok(addrs)
    }
}

/// Globally routable unicast (not loopback, private, link-local, CGNAT, documentation, …).
pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 shared (CGNAT)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated)
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0))
            // ::/96 IPv4-compatible
        }
    }
}

/// A DNS name under a known public suffix (not a bare suffix, not an IP, not an intranet name).
pub(crate) fn public_host(host: &str) -> bool {
    const SPECIAL: [&str; 9] = [
        "localhost",
        "local",
        "localdomain",
        "internal",
        "test",
        "invalid",
        "example",
        "onion",
        "arpa",
    ];
    if host.is_empty()
        || host.len() > 253
        || !host.contains('.')
        || host.parse::<IpAddr>().is_ok()
        || host.starts_with('[')
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return false;
    }
    let tld = host.rsplit('.').next().unwrap_or_default();
    if SPECIAL.contains(&tld) {
        return false;
    }
    psl::domain(host.as_bytes()).is_some_and(|d| d.suffix().is_known())
}

/// Why a request produced nothing.
#[derive(Debug)]
enum Fail {
    /// No answer at all (DNS, connect, TLS, timeout): the host is down or blocked.
    Unreachable(String),
    /// An answer we can't use: an HTTP error, a disallowed redirect, too large, not an image.
    Unusable(String),
}

impl Fail {
    fn message(&self) -> &str {
        match self {
            Fail::Unreachable(m) | Fail::Unusable(m) => m,
        }
    }
}

struct Fetched {
    url: Url,
    content_type: String,
    body: Vec<u8>,
}

/// Whether a response body over the cap is cut (HTML) or refused (images, manifests).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Overflow {
    Truncate,
    Refuse,
}

struct Fetcher<'a> {
    agent: ureq::Agent,
    options: &'a Options,
    deadline: Instant,
    requests: usize,
}

impl<'a> Fetcher<'a> {
    fn new(options: &'a Options) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirects(0)
            .user_agent(USER_AGENT)
            .resolver(PublicResolver {
                resolve_to: options.resolve_to,
            })
            .build();
        Self {
            agent,
            options,
            deadline: Instant::now() + TOTAL_TIMEOUT,
            requests: 0,
        }
    }

    /// Whether `url` may be requested: the allowed scheme, a public host name (or, in tests, any
    /// host, since they all resolve to the test server), no credentials.
    fn allowed(&self, url: &Url) -> bool {
        url.scheme() == self.options.scheme
            && url.username().is_empty()
            && url.password().is_none()
            && url.host_str().is_some_and(|h| {
                public_host(h) || (self.options.resolve_to.is_some() && !h.starts_with('['))
            })
    }

    fn out_of_budget(&self) -> bool {
        self.requests >= MAX_REQUESTS || Instant::now() >= self.deadline
    }

    /// GET with manual redirects, so each hop is checked against [`Fetcher::allowed`].
    fn get(
        &mut self,
        url: &Url,
        accept: &str,
        cap: usize,
        overflow: Overflow,
    ) -> Result<Fetched, Fail> {
        let mut url = url.clone();
        for _ in 0..=MAX_REDIRECTS {
            if !self.allowed(&url) {
                return Err(Fail::Unusable(format!("refused to fetch {url}")));
            }
            let now = Instant::now();
            if self.out_of_budget() {
                return Err(Fail::Unreachable("time or request budget used up".into()));
            }
            self.requests += 1;
            let response = self
                .agent
                .request_url("GET", &url)
                .set("Accept", accept)
                .timeout(REQUEST_TIMEOUT.min(self.deadline.saturating_duration_since(now)))
                .call();
            let response = match response {
                Ok(r) => r,
                Err(ureq::Error::Status(code, _)) => {
                    return Err(Fail::Unusable(format!("HTTP {code} from {url}")))
                }
                Err(ureq::Error::Transport(t)) => {
                    return Err(Fail::Unreachable(format!("{url}: {t}")))
                }
            };
            if (300..400).contains(&response.status()) {
                let next = response
                    .header("Location")
                    .and_then(|l| url.join(l).ok())
                    .ok_or_else(|| Fail::Unusable(format!("bad redirect from {url}")))?;
                url = next;
                continue;
            }
            if !(200..300).contains(&response.status()) {
                return Err(Fail::Unusable(format!(
                    "HTTP {} from {url}",
                    response.status()
                )));
            }
            if overflow == Overflow::Refuse
                && response
                    .header("Content-Length")
                    .and_then(|l| l.trim().parse::<usize>().ok())
                    .is_some_and(|l| l > cap)
            {
                return Err(Fail::Unusable(format!("{url} is too large")));
            }
            let content_type = response
                .header("Content-Type")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let mut body = Vec::new();
            response
                .into_reader()
                .take(cap as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|e| Fail::Unreachable(format!("{url}: {e}")))?;
            if body.len() > cap {
                if overflow == Overflow::Refuse {
                    return Err(Fail::Unusable(format!("{url} is too large")));
                }
                body.truncate(cap);
            }
            return Ok(Fetched {
                url,
                content_type,
                body,
            });
        }
        Err(Fail::Unusable(format!("too many redirects from {url}")))
    }
}

const ACCEPT_HTML: &str = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1";
const ACCEPT_JSON: &str = "application/manifest+json,application/json;q=0.9,*/*;q=0.1";
const ACCEPT_IMAGE: &str = "image/png,image/webp,image/x-icon,image/*;q=0.8,*/*;q=0.1";

/// [`fetch_site_icon`] with explicit connection options (tests use a local HTTP server).
pub(crate) fn fetch_with(domain: &str, options: &Options) -> Result<SiteIcon> {
    let mut fetcher = Fetcher::new(options);
    let mut hosts = vec![domain.to_string()];
    if let Some(registrable) = registrable_domain_of_host(domain) {
        if registrable != domain {
            hosts.push(registrable);
        }
    }
    let mut tried = std::collections::HashSet::new();
    let mut reachable = false;
    let mut last_error = String::new();
    for host in hosts {
        let Ok(root) = Url::parse(&format!("{}://{host}/", options.scheme)) else {
            continue;
        };
        let (page, head) = match fetcher.get(&root, ACCEPT_HTML, HTML_CAP, Overflow::Truncate) {
            Ok(page) => {
                reachable = true;
                let html = page.content_type.is_empty() || page.content_type.contains("html");
                let head = if html {
                    parse_head(&String::from_utf8_lossy(&page.body))
                } else {
                    Head::default()
                };
                (page.url, head)
            }
            // The host doesn't answer: its icon URLs won't either.
            Err(Fail::Unreachable(e)) => {
                last_error = e;
                continue;
            }
            Err(Fail::Unusable(e)) => {
                reachable = true;
                last_error = e;
                (root, Head::default())
            }
        };
        let base = head
            .base
            .as_deref()
            .and_then(|b| page.join(b).ok())
            .unwrap_or_else(|| page.clone());
        for candidate in candidates(&mut fetcher, &page, &base, &head) {
            if !tried.insert(candidate.clone()) {
                continue;
            }
            match fetch_icon(&mut fetcher, &candidate) {
                Ok(icon) => return Ok(icon),
                Err(e) => last_error = e.message().to_string(),
            }
            if fetcher.out_of_budget() {
                break;
            }
        }
    }
    if reachable {
        Err(PassError::NotFound(format!("site icon: {last_error}")))
    } else {
        Err(PassError::Network(format!("site icon: {last_error}")))
    }
}

/// Every icon URL worth trying for one page, best first. Fetches the manifest along the way.
fn candidates(fetcher: &mut Fetcher, page: &Url, base: &Url, head: &Head) -> Vec<Url> {
    let resolve = |href: &str| base.join(href).ok();
    let mut out: Vec<Url> = Vec::new();

    let linked = head
        .links
        .iter()
        .filter(|l| l.rel.iter().any(|r| r == "manifest"))
        .filter_map(|l| resolve(&l.href))
        .take(1)
        .collect::<Vec<_>>();
    let manifests = if linked.is_empty() {
        ["/manifest.json", "/site.webmanifest"]
            .iter()
            .filter_map(|p| page.join(p).ok())
            .collect()
    } else {
        linked
    };
    for manifest in manifests {
        if let Ok(fetched) = fetcher.get(&manifest, ACCEPT_JSON, MANIFEST_CAP, Overflow::Refuse) {
            if let Some(icons) = manifest_icons(&fetched.body, &fetched.url) {
                out.extend(icons);
                break;
            }
        }
    }

    let is_icon_link =
        |l: &&Link| l.rel.iter().any(|r| r == "icon") && !is_svg(l.mime.as_deref(), &l.href);
    let is_apple_link = |l: &&Link| {
        l.rel
            .iter()
            .any(|r| r == "apple-touch-icon" || r == "apple-touch-icon-precomposed")
            && !is_svg(l.mime.as_deref(), &l.href)
    };

    let mut apple: Vec<(u32, &Link)> = head
        .links
        .iter()
        .filter(is_apple_link)
        .map(|l| (largest(l).unwrap_or(180), l))
        .collect();
    apple.sort_by_key(|&(size, _)| (size < 180, if size >= 180 { size } else { u32::MAX - size }));
    out.extend(apple.iter().filter_map(|(_, l)| resolve(&l.href)));

    let mut icons: Vec<(Option<u32>, &Link)> = head
        .links
        .iter()
        .filter(is_icon_link)
        .map(|l| (largest(l), l))
        .collect();
    let mut big: Vec<_> = icons
        .iter()
        .filter(|(s, _)| s.is_some_and(|s| s >= ICON_SIDE))
        .collect();
    big.sort_by_key(|(s, _)| *s);
    out.extend(big.iter().filter_map(|(_, l)| resolve(&l.href)));

    if apple.is_empty() {
        out.extend(page.join("/apple-touch-icon.png").ok());
    }

    icons.retain(|(s, _)| !s.is_some_and(|s| s >= ICON_SIDE));
    icons.sort_by_key(|(s, _)| std::cmp::Reverse(s.map_or(0, |s| s + 1)));
    out.extend(icons.iter().filter_map(|(_, l)| resolve(&l.href)));

    out.extend(page.join("/favicon.ico").ok());
    out
}

fn largest(link: &Link) -> Option<u32> {
    parse_sizes(link.sizes.as_deref()).into_iter().max()
}

fn is_svg(mime: Option<&str>, href: &str) -> bool {
    mime.is_some_and(|m| m.contains("svg")) || {
        let path = href.split(['?', '#']).next().unwrap_or_default();
        path.to_ascii_lowercase().ends_with(".svg")
            || href
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("data:image/svg")
    }
}

/// A manifest's raster icons, best first: 192 px, 512 px, then the closest of at least 128 px.
/// Icons only for `monochrome` use are skipped; `maskable`-only ones come after the others.
fn manifest_icons(body: &[u8], manifest_url: &Url) -> Option<Vec<Url>> {
    #[derive(serde::Deserialize)]
    struct Manifest {
        #[serde(default)]
        icons: Vec<serde_json::Value>,
    }
    let manifest: Manifest = serde_json::from_slice(body).ok()?;
    let mut ranked: Vec<((bool, u32), Url)> = Vec::new();
    for icon in &manifest.icons {
        let field = |k: &str| icon.get(k).and_then(|v| v.as_str());
        let Some(src) = field("src") else { continue };
        let purpose = field("purpose").unwrap_or("any").to_ascii_lowercase();
        let purposes: Vec<&str> = purpose.split_ascii_whitespace().collect();
        if !purposes.is_empty() && purposes.iter().all(|p| *p == "monochrome") {
            continue;
        }
        let maskable_only = !purposes.is_empty() && !purposes.contains(&"any");
        if is_svg(field("type"), src) {
            continue;
        }
        let sizes = parse_sizes(field("sizes"));
        let rank = if sizes.contains(&192) {
            0
        } else if sizes.contains(&512) {
            1
        } else if let Some(s) = sizes.iter().filter(|&&s| s >= ICON_SIDE).min() {
            2 + s
        } else {
            continue;
        };
        if let Ok(url) = manifest_url.join(src) {
            ranked.push(((maskable_only, rank), url));
        }
    }
    ranked.sort_by_key(|(rank, _)| *rank);
    Some(ranked.into_iter().map(|(_, url)| url).collect())
}

/// Downloads (or, for `data:` URLs, decodes) one candidate and normalises it.
fn fetch_icon(fetcher: &mut Fetcher, url: &Url) -> Result<SiteIcon, Fail> {
    if url.scheme() == "data" {
        let bytes = decode_data_url(url.as_str())
            .ok_or_else(|| Fail::Unusable("unreadable data: URL".into()))?;
        return normalize(&bytes, url.as_str());
    }
    let fetched = fetcher.get(url, ACCEPT_IMAGE, ICON_CAP, Overflow::Refuse)?;
    normalize(&fetched.body, fetched.url.as_str())
}

/// The bytes of a base64 `data:` URL, if it is one and fits the icon cap.
fn decode_data_url(url: &str) -> Option<Vec<u8>> {
    let (meta, data) = url.strip_prefix("data:")?.split_once(',')?;
    if !meta.to_ascii_lowercase().ends_with(";base64") || data.len() > ICON_CAP * 4 / 3 + 4 {
        return None;
    }
    let data: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(data.trim_end_matches('='))
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(data.trim_end_matches('='))
        })
        .ok()
}

/// Decodes `bytes` as a raster image and re-encodes it as a PNG of at most [`ICON_SIDE`] px.
fn normalize(bytes: &[u8], source_url: &str) -> Result<SiteIcon, Fail> {
    let bad = |e: String| Fail::Unusable(format!("{source_url}: {e}"));
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| bad(e.to_string()))?;
    match reader.format() {
        Some(
            ImageFormat::Png
            | ImageFormat::Jpeg
            | ImageFormat::Ico
            | ImageFormat::Bmp
            | ImageFormat::WebP
            | ImageFormat::Gif,
        ) => {}
        _ => return Err(bad("not a supported image".into())),
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DECODE_SIDE);
    limits.max_image_height = Some(MAX_DECODE_SIDE);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode().map_err(|e| bad(e.to_string()))?;
    if image.width() < MIN_SIDE || image.height() < MIN_SIDE {
        return Err(bad(format!(
            "{}x{} is too small",
            image.width(),
            image.height()
        )));
    }
    let image = if image.width() > ICON_SIDE || image.height() > ICON_SIDE {
        image.resize(ICON_SIDE, ICON_SIDE, image::imageops::FilterType::Lanczos3)
    } else {
        image
    };
    let rgba = image.to_rgba8();
    if rgba.pixels().all(|p| p.0[3] == 0) {
        return Err(bad("the image is fully transparent".into()));
    }
    let mut png = Vec::new();
    rgba.write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .map_err(|e| bad(e.to_string()))?;
    Ok(SiteIcon {
        bytes: png,
        mime: "image/png".into(),
        width: rgba.width(),
        height: rgba.height(),
        source_url: source_url.chars().take(2048).collect(),
    })
}
