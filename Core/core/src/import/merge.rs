//! Merges several versions of one account into a single item (import clash groups and duplicates).
//! The first member is the base and keeps its id, username and, by default, title. One password and
//! one 2FA secret are kept (by default the most recently modified); a replaced password goes to the
//! history and a replaced 2FA secret to the notes, so nothing is lost.

use std::collections::HashSet;

use super::{ClashField, ImportDecision, MergeChoice, MergeSource};
use crate::i18n::{tr, trn};
use crate::model::{CardData, IdentityData, Item, PasswordHistoryEntry, MAX_PASSWORD_HISTORY};

/// One version of the account.
pub(crate) struct Member<'a> {
    /// `existing`, `import#<n>` or an item id: what a decision names to pick this member.
    pub choice_id: String,
    pub source: MergeSource,
    pub item: &'a Item,
}

/// Comparison key of a website: trimmed, no trailing `/`, lowercase.
pub(crate) fn url_key(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// The 2FA secret's bytes (or the raw value when it doesn't parse), for comparing.
pub(crate) fn totp_secret(totp: Option<&str>) -> Option<Vec<u8>> {
    let t = totp?.trim();
    if t.is_empty() {
        return None;
    }
    Some(
        crate::totp_parse(t.to_string())
            .map(|c| c.secret)
            .unwrap_or_else(|_| t.as_bytes().to_vec()),
    )
}

fn title_key(title: &str) -> String {
    title.trim().to_lowercase()
}

/// Indices of the members holding each distinct non-empty value (the first member per value).
fn distinct<K: PartialEq>(
    members: &[Member],
    key: impl Fn(usize, &Item) -> Option<K>,
) -> Vec<usize> {
    let mut seen: Vec<K> = Vec::new();
    let mut out = Vec::new();
    for (i, m) in members.iter().enumerate() {
        if let Some(k) = key(i, m.item) {
            if !seen.contains(&k) {
                seen.push(k);
                out.push(i);
            }
        }
    }
    out
}

fn password_key(item: &Item) -> Option<String> {
    (!item.password.is_empty()).then(|| item.password.clone())
}

fn totp_key(item: &Item) -> Option<Vec<u8>> {
    totp_secret(item.totp.as_deref())
}

fn title_choice_key(item: &Item) -> Option<String> {
    let k = title_key(&item.title);
    (!k.is_empty()).then_some(k)
}

/// The default among `candidates`: the newest known modification date; the first one when no
/// date is known or on a tie.
fn newest(members: &[Member], candidates: &[usize]) -> Option<usize> {
    let mut best: Option<usize> = None;
    for &i in candidates {
        let at = members[i].item.updated_at;
        match best {
            None => best = Some(i),
            Some(b) if at > 0 && at > members[b].item.updated_at => best = Some(i),
            _ => {}
        }
    }
    best
}

/// The member a decision picked (`id`) among `candidates`, else the default.
fn pick(
    members: &[Member],
    candidates: &[usize],
    id: Option<&str>,
    default: Option<usize>,
) -> Option<usize> {
    id.and_then(|id| {
        candidates
            .iter()
            .copied()
            .find(|&i| members[i].choice_id == id)
    })
    .or(default)
}

/// What the members are, as the UI shows it. No secret values.
pub(crate) struct Analysis {
    pub differs: Vec<ClashField>,
    pub password: Vec<usize>,
    pub totp: Vec<usize>,
    pub title: Vec<usize>,
    pub default_password: Option<usize>,
    pub default_totp: Option<usize>,
    /// Merging would add tags, custom fields or card / identity details to the base. There is no
    /// [`ClashField`] for these (a new variant would break the apps' exhaustive `when`s).
    pub details: bool,
}

impl Analysis {
    /// Nothing but the title would change by merging into the base.
    pub fn identical(&self) -> bool {
        self.differs.iter().all(|f| *f == ClashField::Title) && !self.details
    }

    fn choices(
        &self,
        members: &[Member],
        list: &[usize],
        default: Option<usize>,
    ) -> Vec<MergeChoice> {
        if list.len() < 2 {
            return Vec::new();
        }
        list.iter()
            .map(|&i| MergeChoice {
                id: members[i].choice_id.clone(),
                source: members[i].source,
                label: members[i].item.title.clone(),
                modified_at: members[i].item.updated_at.max(0),
                is_default: Some(i) == default,
            })
            .collect()
    }

    pub fn password_choices(&self, members: &[Member]) -> Vec<MergeChoice> {
        self.choices(members, &self.password, self.default_password)
    }

    pub fn totp_choices(&self, members: &[Member]) -> Vec<MergeChoice> {
        self.choices(members, &self.totp, self.default_totp)
    }

    pub fn title_choices(&self, members: &[Member]) -> Vec<MergeChoice> {
        self.choices(members, &self.title, Some(0))
    }
}

pub(crate) fn analyse(members: &[Member]) -> Analysis {
    let base = members[0].item;
    // A password the base had before, or a 2FA secret already noted in it, is not news.
    let password = distinct(members, |i, item| {
        password_key(item)
            .filter(|p| i == 0 || !base.password_history.iter().any(|h| &h.password == p))
    });
    let totp = distinct(members, |i, item| {
        totp_key(item).filter(|_| {
            i == 0
                || !item
                    .totp
                    .as_deref()
                    .is_some_and(|t| base.notes.contains(t.trim()))
        })
    });
    let title = distinct(members, |_, item| title_choice_key(item));
    let mut differs = Vec::new();
    if title.len() > 1 {
        differs.push(ClashField::Title);
    }
    let fills = |list: &[usize], base_has: bool| list.len() > 1 || (!base_has && !list.is_empty());
    if fills(&password, !base.password.is_empty()) {
        differs.push(ClashField::Password);
    }
    if fills(&totp, base.has_totp()) {
        differs.push(ClashField::Totp);
    }
    let base_urls: HashSet<String> = base.urls.iter().map(|u| url_key(u)).collect();
    if members[1..]
        .iter()
        .any(|m| m.item.urls.iter().any(|u| !base_urls.contains(&url_key(u))))
    {
        differs.push(ClashField::Urls);
    }
    if members[1..].iter().any(|m| {
        let n = m.item.notes.trim();
        !n.is_empty() && !base.notes.contains(n)
    }) {
        differs.push(ClashField::Notes);
    }
    if members[1..].iter().any(|m| {
        m.item.passkeys.iter().any(|p| {
            !base
                .passkeys
                .iter()
                .any(|b| b.credential_id == p.credential_id)
        })
    }) {
        differs.push(ClashField::Passkeys);
    }
    let details = {
        let mut probe = base.clone();
        for m in &members[1..] {
            absorb_details(&mut probe, m.item);
        }
        probe.tags != base.tags
            || probe.fields != base.fields
            || probe.card != base.card
            || probe.identity != base.identity
    };
    Analysis {
        details,
        default_password: newest(members, &password),
        default_totp: newest(members, &totp),
        differs,
        password,
        totp,
        title,
    }
}

/// `2024-05-01` for Unix milliseconds (UTC).
pub(crate) fn ymd(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// The merged item. `decision` must be a `Merge` (anything else merges with the defaults).
/// Keeps the base's id; `now` dates the history entries.
pub(crate) fn merge(members: &[Member], decision: &ImportDecision, now: i64) -> Item {
    let a = analyse(members);
    let (password_from, totp_from, title_from) = match decision {
        ImportDecision::Merge {
            password_from,
            totp_from,
            title_from,
        } => (
            password_from.as_deref(),
            totp_from.as_deref(),
            title_from.as_deref(),
        ),
        _ => (None, None, None),
    };
    let base = members[0].item;
    let mut out = base.clone();

    if let Some(i) = pick(members, &a.title, title_from, None) {
        out.title = members[i].item.title.trim().to_string();
    }
    if out.username.trim().is_empty() {
        if let Some(m) = members.iter().find(|m| !m.item.username.trim().is_empty()) {
            out.username = m.item.username.clone();
        }
    }
    if out.created_at <= 0 {
        out.created_at = members
            .iter()
            .map(|m| m.item.created_at)
            .filter(|&c| c > 0)
            .min()
            .unwrap_or(0);
    }
    out.favorite = members.iter().any(|m| m.item.favorite);

    // Password: the chosen one stays, the others go to the history (newest first).
    if let Some(i) = pick(members, &a.password, password_from, a.default_password) {
        out.password = members[i].item.password.clone();
    }
    let mut history: Vec<PasswordHistoryEntry> = a
        .password
        .iter()
        .map(|&i| &members[i].item.password)
        .filter(|p| **p != out.password)
        .map(|p| PasswordHistoryEntry {
            password: p.clone(),
            replaced_at: now,
        })
        .collect();
    history.extend(
        members
            .iter()
            .flat_map(|m| m.item.password_history.iter().cloned()),
    );
    let mut seen: HashSet<String> = HashSet::from([out.password.clone()]);
    history.retain(|h| !h.password.is_empty() && seen.insert(h.password.clone()));
    history.truncate(MAX_PASSWORD_HISTORY);
    out.password_history = history;

    // 2FA: the chosen secret stays; the others are noted so they aren't lost.
    let mut totp_lines = Vec::new();
    if let Some(i) = pick(members, &a.totp, totp_from, a.default_totp) {
        out.totp = members[i].item.totp.clone();
        let kept = totp_key(members[i].item);
        for &j in &a.totp {
            if totp_key(members[j].item) != kept {
                let value = members[j].item.totp.as_deref().unwrap_or_default().trim();
                totp_lines.push(tr!("merge.previous_totp", date = ymd(now), secret = value));
            }
        }
    }

    let mut url_keys: HashSet<String> = out.urls.iter().map(|u| url_key(u)).collect();
    let mut packages: HashSet<String> =
        out.android_apps.iter().map(|a| a.package.clone()).collect();
    let mut credentials: HashSet<Vec<u8>> = out
        .passkeys
        .iter()
        .map(|p| p.credential_id.clone())
        .collect();
    for m in &members[1..] {
        for url in &m.item.urls {
            if url_keys.insert(url_key(url)) {
                out.push_url_from(&m.item, url);
            }
        }
        for app in &m.item.android_apps {
            if packages.insert(app.package.clone()) {
                out.android_apps.push(app.clone());
            }
        }
        for pk in &m.item.passkeys {
            if credentials.insert(pk.credential_id.clone()) {
                out.passkeys.push(pk.clone());
            }
        }
        append_notes(&mut out.notes, &m.item.notes);
        absorb_details(&mut out, m.item);
    }
    if !totp_lines.is_empty() {
        append_notes(&mut out.notes, &totp_lines.join("\n"));
    }
    out
}

/// Adds what `other` has and `out` lacks: tags and custom fields `out` doesn't have (same name
/// and value), and card / identity fields `out` leaves empty (its own values stay).
pub(crate) fn absorb_details(out: &mut Item, other: &Item) {
    for tag in &other.tags {
        if !out
            .tags
            .iter()
            .any(|t| t.to_lowercase() == tag.to_lowercase())
        {
            out.tags.push(tag.clone());
        }
    }
    for field in &other.fields {
        if !out
            .fields
            .iter()
            .any(|f| f.name == field.name && f.value == field.value)
        {
            out.fields.push(field.clone());
        }
    }
    if out.kind == other.kind {
        if let Some(theirs) = &other.card {
            fill_card(out.card.get_or_insert_with(CardData::default), theirs);
        }
        if let Some(theirs) = &other.identity {
            fill_identity(
                out.identity.get_or_insert_with(IdentityData::default),
                theirs,
            );
        }
    }
}

fn fill(ours: &mut String, theirs: &str) {
    if ours.trim().is_empty() && !theirs.trim().is_empty() {
        *ours = theirs.to_string();
    }
}

fn fill_card(ours: &mut CardData, theirs: &CardData) {
    fill(&mut ours.cardholder_name, &theirs.cardholder_name);
    fill(&mut ours.number, &theirs.number);
    fill(&mut ours.security_code, &theirs.security_code);
    fill(&mut ours.pin, &theirs.pin);
    fill(&mut ours.brand, &theirs.brand);
    if ours.expiry_month == 0 && ours.expiry_year == 0 {
        ours.expiry_month = theirs.expiry_month;
        ours.expiry_year = theirs.expiry_year;
    }
}

fn fill_identity(ours: &mut IdentityData, theirs: &IdentityData) {
    fill(&mut ours.honorific, &theirs.honorific);
    fill(&mut ours.first_name, &theirs.first_name);
    fill(&mut ours.middle_name, &theirs.middle_name);
    fill(&mut ours.last_name, &theirs.last_name);
    fill(&mut ours.email, &theirs.email);
    fill(&mut ours.phone, &theirs.phone);
    fill(&mut ours.address1, &theirs.address1);
    fill(&mut ours.address2, &theirs.address2);
    fill(&mut ours.address3, &theirs.address3);
    fill(&mut ours.city, &theirs.city);
    fill(&mut ours.region, &theirs.region);
    fill(&mut ours.postal_code, &theirs.postal_code);
    fill(&mut ours.country, &theirs.country);
    fill(&mut ours.company, &theirs.company);
    fill(&mut ours.birth_date, &theirs.birth_date);
}

/// Appends `extra` after a blank line unless the notes already contain it.
pub(crate) fn append_notes(notes: &mut String, extra: &str) {
    let extra = extra.trim();
    if extra.is_empty() || notes.contains(extra) {
        return;
    }
    if notes.trim().is_empty() {
        *notes = extra.to_string();
    } else {
        *notes = format!("{}\n\n{extra}", notes.trim_end());
    }
}

/// What merging changed in `before`, for the preview (`["password", "2FA", "website"]`).
pub(crate) fn changes(before: &Item, after: &Item) -> Vec<String> {
    let mut out = Vec::new();
    if before.title != after.title {
        out.push(tr!("merge.title"));
    }
    if before.password != after.password {
        out.push(if before.password.is_empty() {
            tr!("merge.password")
        } else {
            tr!("merge.new_password")
        });
    }
    if totp_key(before) != totp_key(after) {
        out.push(tr!("merge.totp"));
    }
    let urls = after.urls.len().saturating_sub(before.urls.len());
    if urls > 0 {
        out.push(trn!("merge.websites", urls));
    }
    let passkeys = after.passkeys.len().saturating_sub(before.passkeys.len());
    if passkeys > 0 {
        out.push(trn!("merge.passkeys", passkeys));
    }
    if before.notes != after.notes {
        out.push(tr!("merge.notes"));
    }
    if before.tags != after.tags {
        out.push(tr!("merge.tags"));
    }
    if before.fields != after.fields {
        out.push(tr!("merge.custom_fields"));
    }
    if before.card != after.card {
        out.push(tr!("merge.card_details"));
    }
    if before.identity != after.identity {
        out.push(tr!("merge.identity_details"));
    }
    out
}

/// `before` and `after` hold the same data (ignoring the version stamps).
pub(crate) fn same_content(before: &Item, after: &Item) -> bool {
    let strip = |i: &Item| Item {
        updated_at: 0,
        ..i.clone()
    };
    strip(before) == strip(after)
}
