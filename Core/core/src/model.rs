use serde::{Deserialize, Serialize};

/// An Android app linked to a login. When `cert_sha256` is set, the app only matches if its
/// signing certificate digest matches too, so a look-alike package cannot get the credential.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AndroidApp {
    pub package: String,
    /// Hex SHA-256 of the signing certificate; case and `:` separators are ignored.
    #[serde(default)]
    pub cert_sha256: Option<String>,
    /// Set by the user: the login is never suggested or filled automatically for this app, only
    /// when picked by hand. Left out of the JSON when false, so other entries seal unchanged.
    #[serde(default, skip_serializing_if = "is_false")]
    #[cfg_attr(feature = "uniffi", uniffi(default = false))]
    pub never_show: bool,
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// Which pages a website entry of a login is suggested and filled on ([`Item::url_rules`]).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug, Default, Hash)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum UrlMatch {
    /// The entry's site and all its subdomains (the same registrable domain).
    #[default]
    Subdomains,
    /// The entry's host only, and its port when the entry names one.
    Host,
    /// Never suggested or filled automatically; the login is still found by search and filled
    /// when picked by hand.
    Never,
}

impl<'de> Deserialize<'de> for UrlMatch {
    /// Tolerant: a rule a newer client invented reads as the default, so one item never makes the
    /// whole vault unreadable.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "host" => UrlMatch::Host,
            "never" => UrlMatch::Never,
            _ => UrlMatch::Subdomains,
        })
    }
}

/// The rule of one website entry of a login: `url` is the entry exactly as in [`Item::urls`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct UrlRule {
    pub url: String,
    #[serde(default)]
    pub rule: UrlMatch,
}

/// The rule of `url` among `rules` ([`Item::url_rules`]): [`UrlMatch::Subdomains`] when it has
/// none.
pub fn url_rule_of(rules: &[UrlRule], url: &str) -> UrlMatch {
    rules
        .iter()
        .find(|r| r.url == url)
        .map_or(UrlMatch::Subdomains, |r| r.rule)
}

/// `rules` as stored: only rules other than the default, one per entry, for entries `urls` has.
pub(crate) fn normalize_url_rules(urls: &[String], rules: &[UrlRule]) -> Vec<UrlRule> {
    let mut out: Vec<UrlRule> = Vec::new();
    for rule in rules {
        if rule.rule != UrlMatch::Subdomains
            && urls.contains(&rule.url)
            && !out.iter().any(|r| r.url == rule.url)
        {
            out.push(rule.clone());
        }
    }
    out
}

/// What an item is. `Card` and `Identity` keep their data in [`Item::card`] / [`Item::identity`].
///
/// The vault file stores `Card` and `Identity` items with `"kind": "note"` because older clients reject an
/// unknown kind and would refuse the whole vault (see `Item::stored_json`). An unknown kind from a newer
/// client reads as a `Note`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug, Default, Hash)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    #[default]
    Login,
    Note,
    /// A payment card ([`CardData`]).
    Card,
    /// Personal details for forms ([`IdentityData`]).
    Identity,
}

impl ItemKind {
    /// The kind's name in JSON (`login`, `note`, `card`, `identity`).
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Login => "login",
            ItemKind::Note => "note",
            ItemKind::Card => "card",
            ItemKind::Identity => "identity",
        }
    }

    /// The kind named `s` (case-insensitive); anything unknown is a `Note`.
    pub fn parse(s: &str) -> ItemKind {
        match s.trim().to_ascii_lowercase().as_str() {
            "login" => ItemKind::Login,
            "card" => ItemKind::Card,
            "identity" => ItemKind::Identity,
            _ => ItemKind::Note,
        }
    }
}

impl<'de> Deserialize<'de> for ItemKind {
    /// Tolerant: a kind a newer client invented reads as a `Note`, so one item never breaks the vault.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(ItemKind::parse(&s))
    }
}

/// How a custom field is shown and filled.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug, Default, Hash)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// Plain text, shown.
    #[default]
    Text,
    /// A secret: masked until revealed, never in summaries or search.
    Hidden,
    /// A web address (clickable).
    Url,
}

impl<'de> Deserialize<'de> for FieldKind {
    /// Tolerant: an unknown kind (from a newer client) reads as `Hidden`, the safe choice.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "text" => FieldKind::Text,
            "url" => FieldKind::Url,
            _ => FieldKind::Hidden,
        })
    }
}

/// A custom field of an item (`name: value`), e.g. a security question or a customer number.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CustomField {
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub name: String,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub value: String,
    /// No Kotlin default (UniFFI has no enum defaults): pass `FieldKind.TEXT` etc.
    #[serde(default)]
    pub kind: FieldKind,
}

impl std::fmt::Debug for CustomField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// A payment card ([`ItemKind::Card`]). Sealed with the item like every other field. Empty
/// strings and 0 mean "not set"; empty values are left out of the JSON.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CardData {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub cardholder_name: String,
    /// The card number, digits only once saved (`Vault::upsert` drops spaces and dashes).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub number: String,
    /// 1..=12, 0 if unknown.
    #[serde(default, skip_serializing_if = "is_zero")]
    #[cfg_attr(feature = "uniffi", uniffi(default = 0))]
    pub expiry_month: u32,
    /// Four digits (`Vault::upsert` turns `27` into `2027`), 0 if unknown.
    #[serde(default, skip_serializing_if = "is_zero")]
    #[cfg_attr(feature = "uniffi", uniffi(default = 0))]
    pub expiry_year: u32,
    /// CVV / CVC.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub security_code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub pin: String,
    /// Derived from the number by `Vault::upsert` ([`card_brand`]): `visa`, `mastercard`,
    /// `amex`, `discover`, `diners`, `jcb`, `unionpay`, `maestro`, `mir`; kept as given when the
    /// number says nothing (e.g. no number), `""` if unknown.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub brand: String,
}

impl CardData {
    /// The last four digits of the number (fewer if it is shorter), `""` without a number. The
    /// only part of the number that summaries, search and previews ever show.
    pub fn last4(&self) -> String {
        let digits: Vec<char> = self.number.chars().filter(char::is_ascii_digit).collect();
        digits[digits.len().saturating_sub(4)..].iter().collect()
    }
}

impl std::fmt::Debug for CardData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardData")
            .field("brand", &self.brand)
            .field("last4", &self.last4())
            .field("expiry_month", &self.expiry_month)
            .field("expiry_year", &self.expiry_year)
            .finish_non_exhaustive()
    }
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

/// Personal details for filling forms ([`ItemKind::Identity`]). Sealed with the item. Empty
/// strings mean "not set" and are left out of the JSON.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct IdentityData {
    /// Mr, Ms, Dr…
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub honorific: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub first_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub middle_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub last_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub email: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub phone: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub address1: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub address2: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub address3: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub city: String,
    /// State, province, county.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub region: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub postal_code: String,
    /// As entered (a name or an ISO 3166 code).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub country: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub company: String,
    /// `YYYY-MM-DD` when known (imports keep other spellings as they are), `""` if not set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub birth_date: String,
}

impl IdentityData {
    /// First, middle and last name joined with spaces.
    pub fn full_name(&self) -> String {
        [&self.first_name, &self.middle_name, &self.last_name]
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Whether every field is empty.
    pub fn is_empty(&self) -> bool {
        *self == IdentityData::default()
    }
}

impl std::fmt::Debug for IdentityData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityData").finish_non_exhaustive()
    }
}

/// The card network of a card number from its leading digits (IIN ranges): `visa`,
/// `mastercard`, `amex`, `discover`, `diners`, `jcb`, `unionpay`, `maestro`, `mir`, or `""`.
/// Spaces and dashes are ignored.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn card_brand(number: String) -> String {
    let digits: String = number.chars().filter(char::is_ascii_digit).collect();
    let prefix = |n: usize| -> u32 {
        digits
            .get(..n.min(digits.len()))
            .and_then(|p| p.parse().ok())
            .unwrap_or(0)
    };
    if digits.len() < 2 {
        return if digits.starts_with('4') {
            "visa".into()
        } else {
            String::new()
        };
    }
    let (p1, p2, p3, p4, p6) = (prefix(1), prefix(2), prefix(3), prefix(4), prefix(6));
    let brand = if digits.len() >= 4 && (2200..=2204).contains(&p4) {
        "mir"
    } else if p1 == 4 {
        "visa"
    } else if p2 == 34 || p2 == 37 {
        "amex"
    } else if (51..=55).contains(&p2) || (digits.len() >= 4 && (2221..=2720).contains(&p4)) {
        "mastercard"
    } else if p4 == 6011
        || (digits.len() >= 3 && (644..=649).contains(&p3))
        || p2 == 65
        || (digits.len() >= 6 && (622_126..=622_925).contains(&p6))
    {
        "discover"
    } else if digits.len() >= 4 && (3528..=3589).contains(&p4) {
        "jcb"
    } else if (digits.len() >= 3 && (300..=305).contains(&p3)) || p2 == 36 || p2 == 38 || p2 == 39 {
        "diners"
    } else if p2 == 62 || p2 == 81 {
        "unionpay"
    } else if p2 == 50 || (56..=58).contains(&p2) || p2 == 63 || p2 == 67 {
        "maestro"
    } else {
        ""
    };
    brand.to_string()
}

/// The display name of a [`card_brand`] id (`amex` → `American Express`); other values are
/// capitalised as they are, `""` stays `""`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn card_brand_name(brand: String) -> String {
    match brand.as_str() {
        "visa" => "Visa".into(),
        "mastercard" => "Mastercard".into(),
        "amex" => "American Express".into(),
        "discover" => "Discover".into(),
        "diners" => "Diners Club".into(),
        "jcb" => "JCB".into(),
        "unionpay" => "UnionPay".into(),
        "maestro" => "Maestro".into(),
        "mir" => "Mir".into(),
        other => {
            let mut c = other.chars();
            c.next()
                .map(|f| f.to_uppercase().chain(c).collect())
                .unwrap_or_default()
        }
    }
}

/// Whether a card number passes the Luhn check (12 to 19 digits; spaces and dashes ignored).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn card_number_valid(number: String) -> bool {
    if number
        .chars()
        .any(|c| !(c.is_ascii_digit() || c == ' ' || c == '-'))
    {
        return false;
    }
    let digits: Vec<u32> = number.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(12..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// A WebAuthn credential (ES256) stored in the vault.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Passkey {
    #[serde(with = "b64")]
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    #[serde(default)]
    pub rp_name: Option<String>,
    #[serde(with = "b64")]
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    /// PKCS#8 DER of the P-256 private key.
    #[serde(with = "b64")]
    pub private_key_pkcs8: Vec<u8>,
    #[serde(default)]
    pub sign_count: u32,
    #[serde(default = "yes")]
    pub discoverable: bool,
    #[serde(default)]
    pub created_at: i64,
}

fn yes() -> bool {
    true
}

impl std::fmt::Debug for Passkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkey")
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("credential_id", &crate::encoding::hex(&self.credential_id))
            .finish_non_exhaustive()
    }
}

/// A vault entry. A login keeps everything for one account (password, TOTP secret, passkeys)
/// so one fill can complete the whole sign-in.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Item {
    /// Empty for a new item; `Vault::upsert` assigns one.
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub id: String,
    #[serde(default)]
    pub kind: ItemKind,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub title: String,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub username: String,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub password: String,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = []))]
    pub urls: Vec<String>,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = []))]
    pub android_apps: Vec<AndroidApp>,
    /// `otpauth://` URI or bare base32 secret.
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub totp: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = []))]
    pub passkeys: Vec<Passkey>,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub notes: String,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = false))]
    pub favorite: bool,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = 0))]
    pub created_at: i64,
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = 0))]
    pub updated_at: i64,
    /// Passwords this item had before, newest first (at most [`MAX_PASSWORD_HISTORY`]). Left out of the
    /// JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = []))]
    pub password_history: Vec<PasswordHistoryEntry>,
    // Fields below are newer than the first vault format: `serde(default)` so older files open, omitted
    // from the JSON when empty so items that don't use them seal exactly as before.
    /// The card of an [`ItemKind::Card`] item (`None` for every other kind: `Vault::upsert`
    /// clears it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub card: Option<CardData>,
    /// The details of an [`ItemKind::Identity`] item (`None` for every other kind).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub identity: Option<IdentityData>,
    /// Custom fields, in display order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = []))]
    pub fields: Vec<CustomField>,
    /// Tags (folders). `/` nests them (`Work/Clients`). `Vault::upsert` trims them, drops empty
    /// ones and duplicates (case-insensitive).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = []))]
    pub tags: Vec<String>,
    /// When the item was moved to the trash (Unix ms); `None`: not in the trash. Trashed items
    /// are left out of every list and finder and purged after [`TRASH_RETENTION_MS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub trashed_at: Option<i64>,
    /// When the password was last set or changed (Unix ms), maintained by `Vault::upsert`; 0 if
    /// unknown (older items, or saved by an older client): `updated_at` stands in.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    #[cfg_attr(feature = "uniffi", uniffi(default = 0))]
    pub password_changed_at: i64,
    /// How [`Item::urls`] entries match pages, for entries whose rule is not the default
    /// ([`UrlMatch::Subdomains`]). Keyed by the entry, not its place, so a client that reorders or
    /// edits the list without knowing the rules can't move a rule to another entry; a rule whose
    /// entry is gone is dropped by `Vault::upsert`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "uniffi", uniffi(default = []))]
    pub url_rules: Vec<UrlRule>,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

/// How long an item stays in the trash before it is purged for good (30 days).
pub const TRASH_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Most previous passwords kept per item.
pub const MAX_PASSWORD_HISTORY: usize = 20;

/// A password an item used to have.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordHistoryEntry {
    pub password: String,
    /// When it was replaced (Unix milliseconds).
    #[serde(default)]
    pub replaced_at: i64,
}

impl std::fmt::Debug for PasswordHistoryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordHistoryEntry")
            .field("replaced_at", &self.replaced_at)
            .finish_non_exhaustive()
    }
}

impl Item {
    /// The rule of website entry `url` ([`Item::url_rules`]).
    pub fn url_rule(&self, url: &str) -> UrlMatch {
        url_rule_of(&self.url_rules, url)
    }

    /// Adds website entry `url` of `from` (another item merged into this one) with its rule.
    pub(crate) fn push_url_from(&mut self, from: &Item, url: &str) {
        self.urls.push(url.to_string());
        let rule = from.url_rule(url);
        if rule != UrlMatch::Subdomains {
            self.url_rules.push(UrlRule {
                url: url.to_string(),
                rule,
            });
        }
    }

    pub fn has_totp(&self) -> bool {
        self.totp.as_deref().is_some_and(|t| !t.trim().is_empty())
    }

    /// Whether the item is in the trash.
    pub fn is_trashed(&self) -> bool {
        self.trashed_at.is_some()
    }

    /// Keeps `old`, a password this item had until `at` (Unix ms), as the newest entry of its
    /// [`Item::password_history`] (at most [`MAX_PASSWORD_HISTORY`]). Nothing for an empty
    /// password, the current one, or one the history has already.
    pub(crate) fn keep_replaced_password(&mut self, old: &str, at: i64) {
        if old.is_empty()
            || old == self.password
            || self.password_history.iter().any(|h| h.password == old)
        {
            return;
        }
        self.password_history.insert(
            0,
            PasswordHistoryEntry {
                password: old.to_string(),
                replaced_at: at,
            },
        );
        self.password_history.truncate(MAX_PASSWORD_HISTORY);
    }

    /// The item as sealed in the vault file. A `Card` or `Identity` is written with
    /// `"kind": "note"` so clients that lack those kinds still open the vault (see [`ItemKind`]);
    /// [`Item::from_stored_json`] reads it back.
    pub(crate) fn stored_json(&self) -> serde_json::Result<Vec<u8>> {
        match self.kind {
            ItemKind::Card | ItemKind::Identity => {
                let mut value = serde_json::to_value(self)?;
                if let Some(obj) = value.as_object_mut() {
                    obj.insert("kind".into(), ItemKind::Note.as_str().into());
                }
                serde_json::to_vec(&value)
            }
            _ => serde_json::to_vec(self),
        }
    }

    /// [`Item::stored_json`] as a JSON value, for the vault to add its merge metadata to.
    pub(crate) fn stored_value(&self) -> serde_json::Result<serde_json::Value> {
        let mut value = serde_json::to_value(self)?;
        if matches!(self.kind, ItemKind::Card | ItemKind::Identity) {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("kind".into(), ItemKind::Note.as_str().into());
            }
        }
        Ok(value)
    }

    /// Reads an item sealed by [`Item::stored_json`] (or by any older client). The vault reads
    /// it together with its merge metadata (`vault::item_and_meta`).
    #[cfg(test)]
    pub(crate) fn from_stored_json(bytes: &[u8]) -> serde_json::Result<Item> {
        Ok(serde_json::from_slice::<Item>(bytes)?.read_back())
    }

    /// An item as [`Item::stored_json`] wrote it, made what it was: a card or identity stored
    /// as a note for older clients gets its kind back.
    pub(crate) fn read_back(mut self) -> Item {
        if self.kind == ItemKind::Note {
            if self.card.is_some() {
                self.kind = ItemKind::Card;
            } else if self.identity.is_some() {
                self.kind = ItemKind::Identity;
            }
        }
        self
    }

    /// Cleans up what an app hands to `Vault::upsert`: card or identity only on its own kind, card number
    /// digits only, brand derived, years expanded, tags de-duplicated, empty custom fields dropped.
    pub(crate) fn normalize(&mut self) -> crate::Result<()> {
        if self.kind == ItemKind::Card {
            let card = self.card.get_or_insert_with(CardData::default);
            if card.number.chars().any(|c| c.is_ascii_digit()) {
                let cleaned: String = card
                    .number
                    .chars()
                    .filter(|c| !matches!(c, ' ' | '-' | '.' | '\u{a0}'))
                    .collect();
                card.number = cleaned;
            } else {
                card.number = card.number.trim().to_string();
            }
            let brand = card_brand(card.number.clone());
            if !brand.is_empty() {
                card.brand = brand;
            } else {
                card.brand = card.brand.trim().to_ascii_lowercase();
            }
            if card.expiry_month > 12 {
                return Err(crate::PassError::InvalidInput(crate::i18n::tr!(
                    "model.expiry_month"
                )));
            }
            if card.expiry_year > 0 && card.expiry_year < 100 {
                card.expiry_year += 2000;
            }
            if card.expiry_year > 9999 {
                return Err(crate::PassError::InvalidInput(crate::i18n::tr!(
                    "model.expiry_year"
                )));
            }
            if self.title.trim().is_empty() {
                let last4 = card.last4();
                self.title = match (card.brand.is_empty(), last4.is_empty()) {
                    (false, false) => {
                        format!("{} •••• {last4}", card_brand_name(card.brand.clone()))
                    }
                    (true, false) => crate::i18n::tr!("model.card_title", last4 = last4),
                    (false, true) => card_brand_name(card.brand.clone()),
                    (true, true) => String::new(),
                };
            }
        } else {
            self.card = None;
        }
        if self.kind == ItemKind::Identity {
            self.identity.get_or_insert_with(IdentityData::default);
        } else {
            self.identity = None;
        }
        self.tags = normalize_tags(&self.tags);
        self.fields
            .retain(|f| !(f.name.trim().is_empty() && f.value.is_empty()));
        self.url_rules = normalize_url_rules(&self.urls, &self.url_rules);
        Ok(())
    }
}

/// Tags as stored: each `/`-separated segment trimmed, empty segments and tags dropped,
/// duplicates (case-insensitive) removed, first spelling kept.
pub(crate) fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tag in tags {
        let clean = tag
            .split('/')
            .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        if !clean.is_empty() && !out.iter().any(|t| t.to_lowercase() == clean.to_lowercase()) {
            out.push(clean);
        }
    }
    out
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("urls", &self.urls)
            .field("android_apps", &self.android_apps)
            .field("has_totp", &self.has_totp())
            .field("passkeys", &self.passkeys)
            .field("password_history", &self.password_history.len())
            .field("card", &self.card)
            .field("identity", &self.identity.is_some())
            .field("fields", &self.fields)
            .field("tags", &self.tags)
            .field("trashed_at", &self.trashed_at)
            .field("url_rules", &self.url_rules)
            .finish_non_exhaustive()
    }
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::encoding::b64_encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        crate::encoding::b64_decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_kinds_read_as_safe_defaults() {
        let item: Item = serde_json::from_str(r#"{"kind": "ssh_key", "title": "T"}"#).unwrap();
        assert_eq!(item.kind, ItemKind::Note);
        let field: CustomField =
            serde_json::from_str(r#"{"name": "n", "value": "v", "kind": "otp"}"#).unwrap();
        assert_eq!(field.kind, FieldKind::Hidden);
        for kind in [
            ItemKind::Login,
            ItemKind::Note,
            ItemKind::Card,
            ItemKind::Identity,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
            assert_eq!(serde_json::from_str::<ItemKind>(&json).unwrap(), kind);
        }
    }

    #[test]
    fn stored_json_hides_new_kinds_from_older_clients() {
        let card = Item {
            kind: ItemKind::Card,
            card: Some(CardData::default()),
            ..Default::default()
        };
        let stored: serde_json::Value =
            serde_json::from_slice(&card.stored_json().unwrap()).unwrap();
        assert_eq!(stored["kind"], "note");
        assert_eq!(
            Item::from_stored_json(&card.stored_json().unwrap()).unwrap(),
            card
        );
        let note = Item {
            kind: ItemKind::Note,
            ..Default::default()
        };
        assert_eq!(
            Item::from_stored_json(&note.stored_json().unwrap())
                .unwrap()
                .kind,
            ItemKind::Note
        );
        assert_eq!(
            serde_json::to_string(&note).unwrap(),
            String::from_utf8(note.stored_json().unwrap()).unwrap()
        );
    }

    #[test]
    fn tags_are_normalised() {
        let tags = normalize_tags(&[
            " Work / Clients ".into(),
            "work/clients".into(),
            "".into(),
            "/".into(),
            "Home  Office".into(),
        ]);
        assert_eq!(tags, ["Work/Clients", "Home Office"]);
    }
}
