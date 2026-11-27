//! Fuzzy search shared by every app, so a query finds the same items everywhere.
//!
//! Whitespace-separated tokens must each match somewhere (AND), ignoring case and common diacritics.
//! `tag:<name>` or `#<name>` filters by tag (including nested tags). Each token scores its best match
//! (whole field, word, word start, substring, typo, letters in order); items rank by total score, then
//! favorites, usage ([`crate::usage`]) and title. Secrets are never searched: summaries go without notes.

use std::collections::HashMap;

use crate::matching::{parse_loose, registrable_domain_of_host};
use crate::model::Item;
use crate::summary::{is_web_entry, ItemSummary};

/// Match kinds, best first (before the field's weight).
const WHOLE_FIELD: u32 = 120;
const WORD: u32 = 100;
const WORD_PREFIX: u32 = 80;
const SUBSTRING: u32 = 50;
const TYPO_1: u32 = 30;
const TYPO_2: u32 = 25;
const PREFIX_TYPO_1: u32 = 22;
const PREFIX_TYPO_2: u32 = 18;
const SUBSEQUENCE: u32 = 15;
/// A title whose first word matches (or starts with) the token.
const TITLE_START: u32 = 5;

/// Field weights, in percent.
const W_TITLE: u32 = 100;
const W_DOMAIN: u32 = 100;
const W_USERNAME: u32 = 90;
const W_PASSKEY: u32 = 80;
const W_SUBDOMAIN: u32 = 80;
const W_EMAIL_DOMAIN: u32 = 70;
const W_APP: u32 = 60;
const W_PATH: u32 = 50;
const W_OTHER_ENTRY: u32 = 50;
const W_NOTES: u32 = 40;
const W_TAG: u32 = 70;
const W_FIELD: u32 = 40;

/// At most this many tokens count (a pasted paragraph shouldn't stall the list).
const MAX_TOKENS: usize = 16;
/// Words longer than this aren't compared for typos.
const MAX_FUZZY_WORD: usize = 48;

/// Lower case without common Latin diacritics.
pub(crate) fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c.to_ascii_lowercase());
        } else {
            out.extend(c.to_lowercase().map(fold));
        }
    }
    out
}

/// The base letter of a lower-case Latin letter with a diacritic.
fn fold(c: char) -> char {
    match c {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => 'a',
        'ç' | 'ć' | 'ĉ' | 'ċ' | 'č' => 'c',
        'ď' | 'đ' => 'd',
        'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' => 'e',
        'ĝ' | 'ğ' | 'ġ' | 'ģ' => 'g',
        'ĥ' | 'ħ' => 'h',
        'ì' | 'í' | 'î' | 'ï' | 'ĩ' | 'ī' | 'ĭ' | 'į' | 'ı' => 'i',
        'ĵ' => 'j',
        'ķ' => 'k',
        'ĺ' | 'ļ' | 'ľ' | 'ŀ' | 'ł' => 'l',
        'ñ' | 'ń' | 'ņ' | 'ň' => 'n',
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ŏ' | 'ő' => 'o',
        'ŕ' | 'ŗ' | 'ř' => 'r',
        'ś' | 'ŝ' | 'ş' | 'š' | 'ș' => 's',
        'ţ' | 'ť' | 'ŧ' | 'ț' => 't',
        'ù' | 'ú' | 'û' | 'ü' | 'ũ' | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' => 'u',
        'ŵ' => 'w',
        'ý' | 'ÿ' | 'ŷ' => 'y',
        'ź' | 'ż' | 'ž' => 'z',
        other => other,
    }
}

/// `s` without separators (`host maria` and `hostmaria` match each other as substrings).
fn compact(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric()).collect()
}

fn split_words(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
}

/// How many typos a token (or word) of `len` characters may have.
fn allowed_typos(len: usize) -> usize {
    match len {
        0..=3 => 0,
        4..=7 => 1,
        _ => 2,
    }
}

struct Token {
    text: String,
    compact: String,
    chars: Vec<char>,
    /// [`char_bit`] of each letter and digit of `chars`.
    bits: Vec<u64>,
}

impl Token {
    /// How many of the token's characters a text whose [`char_mask`] is `mask` doesn't have at
    /// all. Each of them costs an edit of its own (a swap only moves characters the text has), so
    /// a text missing more than a token's typos allow can't match it in any way, and one missing
    /// any can't match it exactly, as a word, a prefix, a substring or letters in order.
    fn missing(&self, mask: u64) -> usize {
        #[cfg(test)]
        if NO_SHORTCUTS.with(std::cell::Cell::get) {
            return 0;
        }
        self.bits.iter().filter(|&&b| mask & b == 0).count()
    }
}

#[cfg(test)]
thread_local! {
    static NO_SHORTCUTS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f` with [`Token::missing`] ruling nothing out: for tests that the shortcut changes no
/// result.
#[cfg(test)]
pub(crate) fn without_shortcuts<T>(f: impl FnOnce() -> T) -> T {
    NO_SHORTCUTS.with(|s| s.set(true));
    let out = f();
    NO_SHORTCUTS.with(|s| s.set(false));
    out
}

/// A bit for a character, for [`Token::missing`]: letters and digits get their own bit,
/// everything else shares the rest. Two characters with one bit look alike to the check, never
/// the other way round, so it only ever lets more through.
fn char_bit(c: char) -> u64 {
    let i = match c {
        'a'..='z' => c as u32 - 'a' as u32,
        '0'..='9' => 26 + (c as u32 - '0' as u32),
        _ => 36 + (c as u32 % 28),
    };
    1 << i
}

/// Every character of `s` ([`char_bit`]).
fn char_mask(s: &str) -> u64 {
    s.chars().fold(0, |m, c| m | char_bit(c))
}

/// Scratch space for the typo matches, kept across the words of a search.
#[derive(Default)]
struct Scratch {
    chars: Vec<char>,
    rows: Rows,
}

/// Scratch rows for [`osa_row`].
#[derive(Default)]
struct Rows {
    prev2: Vec<usize>,
    prev: Vec<usize>,
    cur: Vec<usize>,
}

/// A parsed search query: its tokens, normalized, and its tag filters.
pub(crate) struct Query {
    tokens: Vec<Token>,
    /// `tag:<name>` / `#<name>` words, as typed.
    tags: Vec<String>,
}

impl Query {
    pub(crate) fn parse(query: &str) -> Query {
        let mut tokens = Vec::new();
        let mut tags = Vec::new();
        for t in query.split_whitespace().take(MAX_TOKENS) {
            let tag = t
                .get(..4)
                .filter(|p| p.eq_ignore_ascii_case("tag:"))
                .map(|_| &t[4..])
                .or_else(|| t.strip_prefix('#'))
                .filter(|rest| !rest.is_empty());
            if let Some(tag) = tag {
                tags.push(tag.to_string());
                continue;
            }
            let text = normalize(t);
            let chars: Vec<char> = text.chars().collect();
            tokens.push(Token {
                compact: compact(&text),
                // Letters and digits only: a separator in the query (`kim.demo`) need not be in
                // the item's text to match its words run together (`kimdemo`).
                bits: chars
                    .iter()
                    .filter(|c| c.is_alphanumeric())
                    .map(|&c| char_bit(c))
                    .collect(),
                chars,
                text,
            });
        }
        Query { tokens, tags }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tokens.is_empty() && self.tags.is_empty()
    }

    /// Whether there is anything to match, not only tag filters.
    pub(crate) fn has_tokens(&self) -> bool {
        !self.tokens.is_empty()
    }
}

/// One searchable field of an item, normalized, while the item's fields are made
/// ([`Doc::fields`]); [`SearchDoc::pack`] keeps them in one buffer.
struct Field {
    text: String,
    compact: String,
    words: Vec<String>,
    weight: u32,
    /// The title: a match on its first word ranks a little higher.
    title: bool,
    /// Letters-in-order matches count (not for notes: too many words).
    subsequence: bool,
}

impl Field {
    fn new(text: &str, weight: u32) -> Field {
        let text = normalize(text.trim());
        Field {
            compact: compact(&text),
            words: split_words(&text).map(str::to_string).collect(),
            text,
            weight,
            title: false,
            subsequence: true,
        }
    }

    /// A field whose words also include the given whole strings (a domain, an email's parts).
    fn with_words(mut self, extra: impl IntoIterator<Item = String>) -> Field {
        for w in extra {
            let w = normalize(&w);
            if !w.is_empty() && !self.words.contains(&w) {
                self.words.push(w);
            }
        }
        self
    }
}

/// A field of a [`SearchDoc`]: where its parts are in the item's buffer.
struct PackedField {
    text: (u32, u32),
    /// The text without separators; the same range as `text` when it has none.
    compact: (u32, u32),
    /// Its words: indexes into [`SearchDoc::words`]; the first starts at `words_at`.
    words: (u32, u32),
    words_at: u32,
    /// [`char_mask`] of the text and every word.
    mask: u64,
    weight: u32,
    title: bool,
    subsequence: bool,
}

/// A field as the matches read it, borrowed from a [`SearchDoc`].
struct FieldView<'a> {
    text: &'a str,
    compact: &'a str,
    buf: &'a str,
    /// For each word: where it ends in `buf`, and its [`char_mask`].
    words: &'a [(u32, u64)],
    words_at: usize,
    mask: u64,
    weight: u32,
    title: bool,
    subsequence: bool,
}

impl FieldView<'_> {
    /// The words with their [`char_mask`].
    fn word_list(&self) -> impl Iterator<Item = (&str, u64)> {
        let mut start = self.words_at;
        self.words.iter().map(move |&(end, mask)| {
            let word = &self.buf[start..end as usize];
            start = end as usize;
            (word, mask)
        })
    }

    /// The best exact, word, prefix or substring match of `token` (before the weight), 0 if none.
    fn plain_match(&self, token: &Token) -> u32 {
        if self.text == token.text {
            return WHOLE_FIELD;
        }
        let mut best = 0;
        for (i, (word, _)) in self.word_list().enumerate() {
            let kind = if word == token.text {
                WORD
            } else if word.starts_with(&token.text) {
                WORD_PREFIX
            } else {
                continue;
            };
            let bonus = if self.title && i == 0 { TITLE_START } else { 0 };
            best = best.max(kind + bonus);
        }
        if best > 0 {
            return best;
        }
        if self.text.contains(&token.text)
            || (!token.compact.is_empty() && self.compact.contains(&token.compact))
        {
            return SUBSTRING;
        }
        0
    }

    /// The best typo or letters-in-order match of `token` against a word, 0 if none.
    fn loose_match(&self, token: &Token, scratch: &mut Scratch) -> u32 {
        let m = token.chars.len();
        let max = allowed_typos(m);
        let mut best = 0;
        for (word, mask) in self.word_list() {
            // Most words are ruled out here, before the distance table is filled in.
            let missing = token.missing(mask);
            let typo = max > 0 && missing <= max;
            let in_order = self.subsequence && m >= 3 && missing == 0;
            if !typo && !in_order {
                continue;
            }
            let buf = &mut scratch.chars;
            buf.clear();
            buf.extend(word.chars());
            let n = buf.len();
            if n > MAX_FUZZY_WORD {
                continue;
            }
            if typo {
                best = best.max(typo_match(&token.chars, buf, &mut scratch.rows));
            }
            if best < SUBSEQUENCE
                && in_order
                && n > m
                && buf[0] == token.chars[0]
                && is_subsequence(&token.chars, buf)
            {
                best = SUBSEQUENCE;
            }
            if best >= TYPO_1 {
                break;
            }
        }
        best
    }
}

/// A typo match of `token` against `word` or the start of it.
fn typo_match(token: &[char], word: &[char], rows: &mut Rows) -> u32 {
    let (m, n) = (token.len(), word.len());
    let max = allowed_typos(m);
    // A whole word needs as many letters as the typos allow (`comx` isn't `com` with a typo).
    let whole_max = max.min(allowed_typos(n));
    if n + max < m {
        return 0;
    }
    let row = osa_row(token, word, rows);
    let whole = row[n];
    let mut best = 0;
    if whole_max > 0 && whole <= whole_max {
        best = if whole <= 1 { TYPO_1 } else { TYPO_2 };
    }
    // The start of a longer word: the best prefix of about the token's length.
    if n > m && best < TYPO_1 {
        let lo = m.saturating_sub(max);
        let hi = (m + max).min(n);
        let prefix = row[lo..=hi].iter().copied().min().unwrap_or(usize::MAX);
        if prefix <= max {
            best = best.max(if prefix <= 1 {
                PREFIX_TYPO_1
            } else {
                PREFIX_TYPO_2
            });
        }
    }
    best
}

/// The last row of the optimal-string-alignment distance table (Damerau-Levenshtein with
/// adjacent transpositions): entry `k` is the distance from `a` to the first `k` chars of `b`.
fn osa_row<'r>(a: &[char], b: &[char], rows: &'r mut Rows) -> &'r [usize] {
    let n = b.len();
    let Rows { prev2, prev, cur } = rows;
    prev2.clear();
    prev2.resize(n + 1, 0);
    prev.clear();
    prev.extend(0..=n);
    cur.clear();
    cur.resize(n + 1, 0);
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=n {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut d = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d = d.min(prev2[j - 2] + 1);
            }
            cur[j] = d;
        }
        std::mem::swap(prev2, prev);
        std::mem::swap(prev, cur);
    }
    prev
}

fn is_subsequence(needle: &[char], hay: &[char]) -> bool {
    let mut it = hay.iter();
    needle.iter().all(|c| it.any(|h| h == c))
}

/// What of an item is searched. Borrowed from an [`Item`] or an [`ItemSummary`].
pub(crate) struct Doc<'a> {
    pub title: &'a str,
    pub username: &'a str,
    pub urls: &'a [String],
    pub apps: Vec<&'a str>,
    pub passkey_names: Vec<&'a str>,
    pub passkey_rp_ids: Vec<&'a str>,
    /// Only while unlocked.
    pub notes: Option<&'a str>,
    pub tags: &'a [String],
    /// Other searchable text with its weight: card and identity details, custom fields.
    pub extra: Vec<(String, u32)>,
}

/// The card and identity details that search sees (never more of a card number than its last
/// four digits).
fn card_identity_extra(
    extra: &mut Vec<(String, u32)>,
    card: Option<(&str, &str, String)>,
    identity: Option<(String, &str, &str)>,
) {
    if let Some((holder, brand, last4)) = card {
        extra.push((holder.to_string(), W_USERNAME));
        extra.push((brand.to_string(), W_APP));
        extra.push((last4, W_USERNAME));
    }
    if let Some((name, email, company)) = identity {
        extra.push((name, W_USERNAME));
        extra.push((email.to_string(), W_USERNAME));
        extra.push((company.to_string(), W_APP));
    }
}

impl<'a> Doc<'a> {
    pub(crate) fn of_item(item: &'a Item) -> Doc<'a> {
        Doc {
            title: &item.title,
            username: &item.username,
            urls: &item.urls,
            apps: item
                .android_apps
                .iter()
                .map(|a| a.package.as_str())
                .collect(),
            passkey_names: item
                .passkeys
                .iter()
                .flat_map(|p| [p.user_name.as_str(), p.user_display_name.as_str()])
                .collect(),
            passkey_rp_ids: item.passkeys.iter().map(|p| p.rp_id.as_str()).collect(),
            notes: Some(&item.notes),
            tags: &item.tags,
            extra: {
                let mut extra = Vec::new();
                card_identity_extra(
                    &mut extra,
                    item.card
                        .as_ref()
                        .map(|c| (c.cardholder_name.as_str(), c.brand.as_str(), c.last4())),
                    item.identity
                        .as_ref()
                        .map(|i| (i.full_name(), i.email.as_str(), i.company.as_str())),
                );
                // The "Available to AI tools" mark is a setting, not the item's data.
                for f in item.fields.iter().filter(|f| !crate::is_ai_access_field(f)) {
                    extra.push((f.name.clone(), W_FIELD));
                    if f.kind != crate::model::FieldKind::Hidden {
                        extra.push((f.value.clone(), W_FIELD));
                    }
                }
                extra
            },
        }
    }

    pub(crate) fn of_summary(item: &'a ItemSummary, notes: Option<&'a str>) -> Doc<'a> {
        Doc {
            title: &item.title,
            username: &item.username,
            urls: &item.urls,
            apps: item
                .android_apps
                .iter()
                .map(|a| a.package.as_str())
                .collect(),
            passkey_names: item
                .passkeys
                .iter()
                .flat_map(|p| [p.user_name.as_str(), p.user_display_name.as_str()])
                .collect(),
            passkey_rp_ids: item.passkeys.iter().map(|p| p.rp_id.as_str()).collect(),
            notes,
            tags: &item.tags,
            extra: {
                let mut extra = Vec::new();
                card_identity_extra(
                    &mut extra,
                    item.card.as_ref().map(|c| {
                        (
                            c.cardholder_name.as_str(),
                            c.brand.as_str(),
                            c.last4.clone(),
                        )
                    }),
                    item.identity
                        .as_ref()
                        .map(|i| (i.full_name.clone(), i.email.as_str(), i.company.as_str())),
                );
                extra
            },
        }
    }

    fn fields(&self) -> Vec<Field> {
        let mut fields = Vec::with_capacity(4 + self.urls.len() * 2);
        if !self.title.trim().is_empty() {
            let mut title = Field::new(self.title, W_TITLE);
            title.title = true;
            fields.push(title);
        }
        let username = self.username.trim();
        if !username.is_empty() {
            match username.rsplit_once('@') {
                Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
                    let mut field = Field::new(username, W_USERNAME);
                    // The domain's words go with the email domain (weighs less).
                    let local = normalize(local);
                    field.words = split_words(&local).map(str::to_string).collect();
                    fields.push(field.with_words([local]));
                    fields.push(domain_field(domain, W_EMAIL_DOMAIN));
                }
                _ => fields.push(Field::new(username, W_USERNAME)),
            }
        }
        for entry in self.urls {
            push_entry_fields(&mut fields, entry);
        }
        for app in &self.apps {
            if !app.trim().is_empty() {
                fields.push(Field::new(app, W_APP).with_words([app.to_string()]));
            }
        }
        for name in &self.passkey_names {
            if !name.trim().is_empty() {
                fields.push(Field::new(name, W_PASSKEY));
            }
        }
        for rp in &self.passkey_rp_ids {
            if !rp.trim().is_empty() {
                fields.push(domain_field(rp, W_PASSKEY));
            }
        }
        for tag in self.tags {
            if !tag.trim().is_empty() {
                fields.push(Field::new(tag, W_TAG));
            }
        }
        for (text, weight) in &self.extra {
            if !text.trim().is_empty() {
                let mut field = Field::new(text, *weight);
                field.subsequence = *weight > W_FIELD;
                fields.push(field);
            }
        }
        if let Some(notes) = self.notes.filter(|n| !n.trim().is_empty()) {
            let mut field = Field::new(notes, W_NOTES);
            field.subsequence = false;
            fields.push(field);
        }
        fields
    }

    /// What [`score`] needs of this item, made once: a list that stays the same between
    /// keystrokes ([`crate::SearchIndex`], [`crate::Vault::search`]) is not read again each time.
    pub(crate) fn index(&self) -> SearchDoc {
        SearchDoc::pack(self.fields(), self.tags)
    }
}

/// A domain (or host) as a field: its labels are words, and so is the whole domain.
fn domain_field(domain: &str, weight: u32) -> Field {
    Field::new(domain, weight).with_words([domain.to_string()])
}

/// The fields of one stored entry: for a website its registrable domain, the rest of its host and
/// its path; for anything else (`windows:<exe>`, app links) the entry itself.
fn push_entry_fields(fields: &mut Vec<Field>, entry: &str) {
    let entry = entry.trim();
    if entry.is_empty() {
        return;
    }
    let url = is_web_entry(entry)
        .then(|| parse_loose(entry))
        .flatten()
        .filter(|u| u.host_str().is_some_and(|h| !h.is_empty()));
    let Some(url) = url else {
        fields.push(Field::new(entry, W_OTHER_ENTRY));
        return;
    };
    let host = url
        .host_str()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let domain = registrable_domain_of_host(&host).unwrap_or_else(|| host.clone());
    fields.push(domain_field(&domain, W_DOMAIN));
    if let Some(sub) = host
        .strip_suffix(domain.as_str())
        .map(|s| s.trim_end_matches('.'))
        .filter(|s| !s.is_empty() && *s != "www")
    {
        let mut field = Field::new(&host, W_SUBDOMAIN);
        field.words = split_words(sub)
            .filter(|w| *w != "www")
            .map(str::to_string)
            .collect();
        fields.push(field.with_words([host.clone()]));
    }
    let path = url.path().trim_matches('/');
    if !path.is_empty() {
        fields.push(Field::new(path, W_PATH));
    }
}

/// An item's searchable fields, normalized and split once ([`Doc::index`]), in one buffer: kept
/// for many keystrokes, an item costs a few allocations instead of a few per field and word.
pub(crate) struct SearchDoc {
    /// Every field's text, its text without separators (when different) and its words.
    buf: Box<str>,
    fields: Box<[PackedField]>,
    /// Every field's words: where each ends in `buf`, and its [`char_mask`].
    words: Box<[(u32, u64)]>,
    tags: Box<[String]>,
    /// Every character of every field ([`Token::missing`]).
    mask: u64,
}

impl SearchDoc {
    fn pack(fields: Vec<Field>, tags: &[String]) -> SearchDoc {
        let size = fields
            .iter()
            .map(|f| {
                f.text.len()
                    + if f.compact == f.text {
                        0
                    } else {
                        f.compact.len()
                    }
                    + f.words.iter().map(String::len).sum::<usize>()
            })
            .sum();
        let mut buf = String::with_capacity(size);
        let mut words = Vec::with_capacity(fields.iter().map(|f| f.words.len()).sum());
        let mut packed = Vec::with_capacity(fields.len());
        let mut all = 0;
        let push = |buf: &mut String, s: &str| {
            let start = buf.len() as u32;
            buf.push_str(s);
            (start, buf.len() as u32)
        };
        for f in &fields {
            let text = push(&mut buf, &f.text);
            let compact = if f.compact == f.text {
                text
            } else {
                push(&mut buf, &f.compact)
            };
            let words_at = buf.len() as u32;
            let first = words.len() as u32;
            let mut mask = char_mask(&f.text);
            for w in &f.words {
                buf.push_str(w);
                let m = char_mask(w);
                mask |= m;
                words.push((buf.len() as u32, m));
            }
            all |= mask;
            packed.push(PackedField {
                text,
                compact,
                words: (first, words.len() as u32),
                words_at,
                mask,
                weight: f.weight,
                title: f.title,
                subsequence: f.subsequence,
            });
        }
        SearchDoc {
            buf: buf.into_boxed_str(),
            fields: packed.into_boxed_slice(),
            words: words.into_boxed_slice(),
            tags: tags.to_vec().into_boxed_slice(),
            mask: all,
        }
    }

    fn views(&self) -> impl Iterator<Item = FieldView<'_>> {
        let range = |(a, b): (u32, u32)| &self.buf[a as usize..b as usize];
        self.fields.iter().map(move |f| FieldView {
            text: range(f.text),
            compact: range(f.compact),
            buf: &self.buf,
            words: &self.words[f.words.0 as usize..f.words.1 as usize],
            words_at: f.words_at as usize,
            mask: f.mask,
            weight: f.weight,
            title: f.title,
            subsequence: f.subsequence,
        })
    }
}

/// The score of `doc` for `query` (higher is better), `None` if a token matches nothing.
pub(crate) fn score(query: &Query, doc: &Doc) -> Option<u32> {
    if !query
        .tags
        .iter()
        .all(|t| crate::summary::has_tag(doc.tags, t))
    {
        return None;
    }
    if query.tokens.is_empty() {
        return Some(0);
    }
    score_fields(query, &doc.index())
}

/// [`score`] of an item read once ([`Doc::index`]).
pub(crate) fn score_indexed(query: &Query, doc: &SearchDoc) -> Option<u32> {
    if !query
        .tags
        .iter()
        .all(|t| crate::summary::has_tag(&doc.tags, t))
    {
        return None;
    }
    if query.tokens.is_empty() {
        return Some(0);
    }
    score_fields(query, doc)
}

fn score_fields(query: &Query, doc: &SearchDoc) -> Option<u32> {
    let mask = doc.mask;
    // A token whose characters the item doesn't have can't match it, by any rule: most items
    // are ruled out here for a query of a few letters.
    if query
        .tokens
        .iter()
        .any(|t| t.missing(mask) > allowed_typos(t.chars.len()))
    {
        return None;
    }
    let fields: Vec<FieldView> = doc.views().collect();
    let mut scratch = Scratch::default();
    let mut total = 0;
    for token in &query.tokens {
        let mut best = 0;
        let missing: Vec<usize> = fields.iter().map(|f| token.missing(f.mask)).collect();
        for (field, &missing) in fields.iter().zip(&missing) {
            if missing == 0 {
                best = best.max(field.plain_match(token) * field.weight / 100);
            }
        }
        // Typos only where they could still beat what matched (and a token of one or two letters
        // has neither typos nor letters in order).
        let max = allowed_typos(token.chars.len());
        let loose = max > 0 || token.chars.len() >= 3;
        for (field, &missing) in fields.iter().zip(&missing) {
            if loose && missing <= max && TYPO_1 * field.weight / 100 > best {
                best = best.max(field.loose_match(token, &mut scratch) * field.weight / 100);
            }
        }
        if best == 0 {
            return None;
        }
        total += best;
    }
    Some(total)
}

/// `items` that match `query`, best first, then by `order` (favorites, then the usage rank: higher
/// first) and title. An empty query returns `items` as given.
pub(crate) fn rank_by<T>(
    items: Vec<T>,
    query: &str,
    score_of: impl Fn(&Query, &T) -> Option<u32>,
    title: impl Fn(&T) -> &str,
    order: impl Fn(&T) -> (bool, i64),
) -> Vec<T> {
    let query = Query::parse(query);
    if query.is_empty() {
        return items;
    }
    let mut found: Vec<(u32, (bool, i64), String, T)> = items
        .into_iter()
        .filter_map(|item| {
            let s = score_of(&query, &item)?;
            Some((s, order(&item), normalize(title(&item)), item))
        })
        .collect();
    if query.tokens.is_empty() {
        // Tag filters only: by title, like an empty query.
        found.sort_by(|a, b| a.2.cmp(&b.2));
    } else {
        found.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then(b.1.cmp(&a.1))
                .then_with(|| a.2.cmp(&b.2))
        });
    }
    found.into_iter().map(|(.., item)| item).collect()
}

/// Fuzzy search over items (titles, usernames, websites, apps, passkey names and notes), best
/// match first, then favorites, then by title. An empty query returns `items` unchanged. For pickers over
/// full items; the vault list uses [`crate::Vault::search`] or [`summaries_search`](crate::summaries_search).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn items_search(items: Vec<Item>, query: String) -> Vec<Item> {
    rank_by(
        items,
        &query,
        |q, i| score(q, &Doc::of_item(i)),
        |i| &i.title,
        |i| (i.favorite, 0),
    )
}

/// [`summaries_search`](crate::summaries_search) that also searches notes: `notes` maps item ids
/// to their notes (only while unlocked; leave it empty when locked).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn summaries_search_with_notes(
    index: Vec<ItemSummary>,
    notes: HashMap<String, String>,
    query: String,
) -> Vec<ItemSummary> {
    let mut index = index;
    if Query::parse(&query).is_empty() {
        index.sort_by_cached_key(|i| i.title.to_lowercase());
        return index;
    }
    rank_by(
        index,
        &query,
        |q, i| score(q, &Doc::of_summary(i, notes.get(&i.id).map(String::as_str))),
        |i| &i.title,
        |i| (i.favorite, i.rank),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AndroidApp, ItemKind};

    fn login(id: &str, title: &str, username: &str, urls: &[&str]) -> Item {
        Item {
            id: id.into(),
            title: title.into(),
            username: username.into(),
            urls: urls.iter().map(|u| u.to_string()).collect(),
            ..Default::default()
        }
    }

    fn vault() -> Vec<Item> {
        vec![
            login(
                "hm",
                "Hostmaria",
                "alex@example.com",
                &["https://www.hostmaria.com/login"],
            ),
            login(
                "hm2",
                "Hostmaria reseller",
                "other@yahoo.com",
                &["hostmaria.com"],
            ),
            login(
                "gm",
                "Gmail",
                "alex@example.com",
                &["https://mail.google.com"],
            ),
            login("gh", "GitHub", "octo", &["https://github.com"]),
            login(
                "gl",
                "GitLab",
                "octo",
                &["https://gitlab.com/users/sign_in"],
            ),
            login("hn", "Hosting notes", "", &[]),
            Item {
                id: "note".into(),
                kind: ItemKind::Note,
                title: "Wi-Fi".into(),
                notes: "Router password is on the fridge, café upstairs".into(),
                ..Default::default()
            },
            Item {
                id: "app".into(),
                title: "Bank".into(),
                username: "Zoë Müller".into(),
                android_apps: vec![AndroidApp {
                    package: "com.examplebank.mobile".into(),
                    cert_sha256: None,
                    ..Default::default()
                }],
                ..Default::default()
            },
        ]
    }

    fn ids(found: Vec<Item>) -> Vec<String> {
        found.into_iter().map(|i| i.id).collect()
    }

    fn search(q: &str) -> Vec<String> {
        ids(items_search(vault(), q.into()))
    }

    #[test]
    fn the_users_example_finds_the_login() {
        assert_eq!(search("alex hostmaria"), ["hm"]);
        assert_eq!(search("hostmaria alex"), ["hm"]);
        assert_eq!(search("ALEX   HostMaria.com"), ["hm"]);
    }

    #[test]
    fn typos_partial_words_and_and() {
        assert_eq!(search("hostmaira alex"), ["hm"]);
        assert_eq!(search("hostmaira")[..2], ["hm", "hm2"]);
        assert_eq!(search("host ale"), ["hm"]);
        assert_eq!(search("ale host"), ["hm"]);
        assert!(search("hostmaria github").is_empty());
        assert_eq!(search("gmail alex"), ["gm"]);
        assert!(search("gtx").is_empty());
        assert_eq!(search("hostmair")[0], "hm");
    }

    #[test]
    fn domains_labels_and_emails() {
        assert_eq!(search("hostmaria.com")[..2], ["hm", "hm2"]);
        assert_eq!(search("yahoo"), ["hm2"]);
        assert_eq!(search("other"), ["hm2"]);
        assert_eq!(search("mail")[0], "gm");
        assert_eq!(search("sign_in"), ["gl"]);
        assert_eq!(search("examplebank"), ["app"]);
        assert_eq!(search("zoe muller"), ["app"]);
        assert_eq!(search("cafe fridge"), ["note"]);
        assert_eq!(search("CAFÉ"), ["note"]);
    }

    #[test]
    fn better_matches_rank_first() {
        let found = search("git");
        assert_eq!(found, ["gh", "gl"]);
        assert_eq!(search("host"), ["hn", "hm", "hm2"]);
        assert_eq!(search("hostmaria"), ["hm", "hm2"]);
        let mut items = vault();
        items[3].notes = "see the router".into();
        items[6].title = "Router".into();
        assert_eq!(ids(items_search(items, "router".into())), ["note", "gh"]);
    }

    #[test]
    fn empty_query_returns_items_unchanged() {
        assert_eq!(search(""), ids(vault()));
        assert_eq!(search("   "), ids(vault()));
    }

    #[test]
    fn usage_breaks_ties_then_title() {
        let index: Vec<ItemSummary> = vault()
            .iter()
            .map(ItemSummary::of)
            .map(|mut s| {
                if s.id == "gl" {
                    s.rank = 10;
                }
                s
            })
            .collect();
        let found = summaries_search_with_notes(index.clone(), HashMap::new(), "git".into());
        let found: Vec<&str> = found.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(found, ["gl", "gh"]);
        assert!(
            summaries_search_with_notes(index.clone(), HashMap::new(), "fridge".into()).is_empty()
        );
        let notes = HashMap::from([("note".to_string(), "on the fridge".to_string())]);
        let found = summaries_search_with_notes(index.clone(), notes, "fridge".into());
        assert_eq!(found.len(), 1);
        let all = summaries_search_with_notes(index, HashMap::new(), " ".into());
        assert_eq!(all[0].title, "Bank");
    }

    #[test]
    fn typo_distances() {
        let c = |s: &str| s.chars().collect::<Vec<_>>();
        assert_eq!(osa_row(&c("ca"), &c("ac"), &mut Rows::default())[2], 1);
        assert_eq!(
            osa_row(&c("kitten"), &c("sitting"), &mut Rows::default())[7],
            3
        );
        assert_eq!(
            typo_match(&c("hostmaira"), &c("hostmaria"), &mut Rows::default()),
            TYPO_1
        );
        assert_eq!(
            typo_match(&c("hostmaira"), &c("hostmariabox"), &mut Rows::default()),
            PREFIX_TYPO_1
        );
        assert_eq!(
            typo_match(&c("hostmrai"), &c("hostmaria"), &mut Rows::default()),
            TYPO_2
        );
        assert_eq!(typo_match(&c("comx"), &c("com"), &mut Rows::default()), 0);
        assert_eq!(
            typo_match(&c("gogle"), &c("google"), &mut Rows::default()),
            TYPO_1
        );
        assert_eq!(
            typo_match(&c("gooogle"), &c("google"), &mut Rows::default()),
            TYPO_1
        );
        assert_eq!(
            typo_match(&c("passybel"), &c("passyble"), &mut Rows::default()),
            TYPO_1
        );
        // Two typos need 8 letters.
        assert_eq!(
            typo_match(&c("pasybel"), &c("passyble"), &mut Rows::default()),
            0
        );
    }

    #[test]
    fn thousands_of_items_stay_fast() {
        let items: Vec<Item> = (0..5000)
            .map(|n| {
                login(
                    &n.to_string(),
                    &format!("Site number {n}"),
                    &format!("user{n}@example{}.com", n % 50),
                    &[&format!("https://www.site{n}.example.org/login")],
                )
            })
            .collect();
        let start = std::time::Instant::now();
        let found = items_search(items, "site4999 usr4999".into());
        assert_eq!(found[0].id, "4999");
        // Generous for debug builds on slow CI machines.
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }
}
