//! Just enough HTML to find `<link>` and `<base>` tags in a page's `<head>`: no DOM, no scripts.
//! The page is untrusted; this only ever extracts attribute strings.

/// One `<link>` tag's interesting attributes (names lower-cased, values entity-decoded).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Link {
    /// The `rel` tokens, lower-cased.
    pub rel: Vec<String>,
    pub href: String,
    pub sizes: Option<String>,
    pub mime: Option<String>,
}

/// The head of an HTML page: its `<link>` tags and the first `<base href>`.
#[derive(Debug, Default)]
pub(crate) struct Head {
    pub links: Vec<Link>,
    pub base: Option<String>,
}

/// Scans `html` up to `</head>` or `<body` for `<link>` and `<base>` tags. Comments, scripts and
/// styles are skipped so markup inside them doesn't count.
pub(crate) fn parse_head(html: &str) -> Head {
    let mut head = Head::default();
    let bytes = html.as_bytes();
    let mut i = 0;
    while let Some(off) = html[i..].find('<') {
        i += off;
        let rest = &html[i..];
        if rest.starts_with("<!--") {
            match rest.find("-->") {
                Some(end) => i += end + 3,
                None => break,
            }
            continue;
        }
        let name_start = i + 1;
        let closing = bytes.get(name_start) == Some(&b'/');
        let name_from = if closing { name_start + 1 } else { name_start };
        let name_end = html[name_from..]
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .map_or(html.len(), |e| name_from + e);
        let name = html[name_from..name_end].to_ascii_lowercase();
        let (attrs, tag_end) = parse_attrs(html, name_end);
        i = tag_end;
        if closing {
            if name == "head" {
                break;
            }
            continue;
        }
        match name.as_str() {
            "body" => break,
            "script" | "style" | "noscript" | "template" | "textarea" | "title" => {
                let close = format!("</{name}");
                match find_ci(&html[i..], &close) {
                    Some(end) => i += end,
                    None => break,
                }
            }
            "base" if head.base.is_none() => {
                head.base = attr(&attrs, "href");
            }
            "link" => {
                let href = attr(&attrs, "href").unwrap_or_default();
                if href.is_empty() {
                    continue;
                }
                head.links.push(Link {
                    rel: attr(&attrs, "rel")
                        .unwrap_or_default()
                        .split_ascii_whitespace()
                        .map(str::to_ascii_lowercase)
                        .collect(),
                    href,
                    sizes: attr(&attrs, "sizes"),
                    mime: attr(&attrs, "type").map(|t| t.trim().to_ascii_lowercase()),
                });
            }
            _ => {}
        }
    }
    head
}

fn attr(attrs: &[(String, String)], name: &str) -> Option<String> {
    attrs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.trim().to_string())
}

/// Case-insensitive ASCII `find`.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// Parses `name=value` attributes from `from` up to the tag's `>`. Returns them and the index
/// just past the `>` (or the end of the input).
fn parse_attrs(html: &str, from: usize) -> (Vec<(String, String)>, usize) {
    let b = html.as_bytes();
    let mut attrs = Vec::new();
    let mut i = from;
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            return (attrs, b.len());
        }
        if b[i] == b'>' {
            return (attrs, i + 1);
        }
        let name_start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        let name = html[name_start..i].to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let quote = b[i];
                let start = i + 1;
                let end = b[start..]
                    .iter()
                    .position(|&c| c == quote)
                    .map_or(b.len(), |e| start + e);
                value = decode_entities(&html[start..end]);
                i = (end + 1).min(b.len());
            } else {
                let start = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                value = decode_entities(&html[start..i]);
            }
        }
        if !name.is_empty() {
            attrs.push((name, value));
        }
    }
}

/// The handful of character references that show up in URLs and `sizes`.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let Some(semi) = rest.bytes().take(12).position(|c| c == b';') else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..semi];
        let decoded = match entity.to_ascii_lowercase().as_str() {
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "lt" => Some('<'),
            "gt" => Some('>'),
            e if e.starts_with("#x") => u32::from_str_radix(&e[2..], 16)
                .ok()
                .and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The square sizes in a `sizes` attribute (`"16x16 32x32"`, `"any"` → none). Non-square entries
/// count by their smaller side.
pub(crate) fn parse_sizes(sizes: Option<&str>) -> Vec<u32> {
    sizes
        .unwrap_or_default()
        .split_ascii_whitespace()
        .filter_map(|s| {
            let (w, h) = s.split_once(['x', 'X'])?;
            let (w, h) = (w.parse::<u32>().ok()?, h.parse::<u32>().ok()?);
            Some(w.min(h))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_links_in_head_only() {
        let html = r#"<!doctype html><html><HEAD>
            <!-- <link rel="icon" href="/commented.png"> -->
            <script>var s = '<link rel="icon" href="/script.png">';</script>
            <link rel=icon href=/a.png sizes=32x32>
            <LINK REL="Apple-Touch-Icon" HREF='/apple.png?a=1&amp;b=2'>
            <link rel="manifest" href="/site.webmanifest" />
            <base href="https://cdn.example.com/">
            <link rel="shortcut icon" type="image/x-icon" href="/fav.ico">
            </head><body><link rel="icon" href="/body.png"></body>"#;
        let head = parse_head(html);
        let hrefs: Vec<_> = head.links.iter().map(|l| l.href.as_str()).collect();
        assert_eq!(
            hrefs,
            [
                "/a.png",
                "/apple.png?a=1&b=2",
                "/site.webmanifest",
                "/fav.ico"
            ]
        );
        assert_eq!(head.links[1].rel, ["apple-touch-icon"]);
        assert_eq!(head.links[3].rel, ["shortcut", "icon"]);
        assert_eq!(head.links[3].mime.as_deref(), Some("image/x-icon"));
        assert_eq!(head.links[0].sizes.as_deref(), Some("32x32"));
        assert_eq!(head.base.as_deref(), Some("https://cdn.example.com/"));
    }

    #[test]
    fn tolerates_truncated_and_odd_markup() {
        assert!(parse_head("").links.is_empty());
        assert!(parse_head("<link rel=icon href=").links.is_empty());
        assert!(parse_head("<!-- unterminated <link rel=icon href=/x>")
            .links
            .is_empty());
        let head = parse_head("<link rel=icon href=\"/x.png");
        assert_eq!(head.links[0].href, "/x.png");
        let head = parse_head("<link rel=icon href=/&#x2F;y&#47;z.png&bogus;>");
        assert_eq!(head.links[0].href, "//y/z.png&bogus;");
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_sizes(Some("16x16 32X32 any 192x180")), [16, 32, 180]);
        assert!(parse_sizes(None).is_empty());
        assert!(parse_sizes(Some("any")).is_empty());
    }
}
