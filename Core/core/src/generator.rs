use rand::seq::SliceRandom;
use rand::Rng;

use crate::{PassError, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordOptions {
    pub length: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Leaves out characters that are easy to confuse (`Il1O0o`).
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: true,
        }
    }
}

const AMBIGUOUS: &str = "Il1O0o";

/// Random password with at least one character from every enabled class.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_password(options: PasswordOptions) -> Result<String> {
    let classes: Vec<Vec<char>> = [
        (options.lowercase, "abcdefghijklmnopqrstuvwxyz"),
        (options.uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (options.digits, "0123456789"),
        (options.symbols, "!@#$%^&*()-_=+[]{};:,.?/~"),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, set)| {
        set.chars()
            .filter(|c| !options.avoid_ambiguous || !AMBIGUOUS.contains(*c))
            .collect()
    })
    .collect();
    if classes.is_empty() {
        return Err(PassError::InvalidInput(crate::i18n::tr!(
            "generator.no_classes"
        )));
    }
    let length = options.length as usize;
    if length < classes.len() || length > 1024 {
        return Err(PassError::InvalidInput(crate::i18n::tr!(
            "generator.bad_length",
            min = classes.len(),
            max = 1024
        )));
    }
    let mut rng = rand::rngs::OsRng;
    let all: Vec<char> = classes.iter().flatten().copied().collect();
    let mut chars: Vec<char> = classes
        .iter()
        .map(|set| *set.choose(&mut rng).expect("non-empty"))
        .collect();
    while chars.len() < length {
        chars.push(*all.choose(&mut rng).expect("non-empty"));
    }
    chars.shuffle(&mut rng);
    Ok(chars.into_iter().collect())
}

/// The EFF large wordlist (7776 common English words, CC BY 3.0 US, https://www.eff.org/dice),
/// one per line. See `THIRD_PARTY_NOTICES.md`.
const PASSPHRASE_WORDS: &str = include_str!("wordlist/eff_large.txt");

/// Fewest words a passphrase has; fewer are raised to this.
pub const PASSPHRASE_MIN_WORDS: u32 = 4;
/// Words the apps start with.
pub const PASSPHRASE_DEFAULT_WORDS: u32 = 6;
/// Most words a passphrase has; more are lowered to this.
pub const PASSPHRASE_MAX_WORDS: u32 = 20;

/// Passphrase of real English words from the EFF large wordlist, each picked uniformly (about
/// 12.9 bits per word), plus one digit at the end of a random word. 6 words are about 78 bits plus
/// the digit.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_passphrase(words: u32, separator: String) -> String {
    let list: Vec<&str> = PASSPHRASE_WORDS.lines().collect();
    let mut rng = rand::rngs::OsRng;
    let words = words.clamp(PASSPHRASE_MIN_WORDS, PASSPHRASE_MAX_WORDS) as usize;
    let digit_word = rng.gen_range(0..words);
    (0..words)
        .map(|i| {
            let mut word = (*list.choose(&mut rng).expect("non-empty")).to_string();
            if i == digit_word {
                word.push(char::from(b'0' + rng.gen_range(0..10)));
            }
            word
        })
        .collect::<Vec<_>>()
        .join(&separator)
}

/// What kind of username [`generate_username`] makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum UsernameKind {
    /// An adjective and a noun: `Swift-Otter` (with the number: `Swift-Otter4821`).
    #[default]
    Words,
    /// One word and four digits: `Otter4821`.
    WordNumber,
    /// Random lowercase letters and digits, starting with a letter: `k3vq9tmz2c`.
    Characters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct UsernameOptions {
    pub kind: UsernameKind,
    /// Words start with a capital letter (`Words`, `WordNumber`).
    pub capitalize: bool,
    /// Four random digits after the words (`Words`; `WordNumber` always has them).
    pub include_number: bool,
    /// Between the words (`Words`): one of [`USERNAME_SEPARATORS`].
    pub separator: String,
    /// `Characters`: 4..=64.
    pub length: u32,
}

impl Default for UsernameOptions {
    fn default() -> Self {
        Self {
            kind: UsernameKind::Words,
            capitalize: true,
            include_number: false,
            separator: "-".into(),
            length: 12,
        }
    }
}

/// Separators a generated username may use (accepted by the sign-up forms we know of).
pub const USERNAME_SEPARATORS: &[&str] = &["", "-", "_", "."];

fn capitalized(word: &str, capitalize: bool) -> String {
    let mut chars = word.chars();
    match (capitalize, chars.next()) {
        (true, Some(first)) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        _ => word.to_string(),
    }
}

fn four_digits(rng: &mut rand::rngs::OsRng) -> String {
    format!("{:04}", rng.gen_range(0..10_000u32))
}

/// `n` random characters from `set` (OS CSPRNG).
fn random_from(set: &[u8], n: usize, rng: &mut rand::rngs::OsRng) -> String {
    (0..n)
        .map(|_| *set.choose(rng).expect("non-empty") as char)
        .collect()
}

const LOWER_DIGITS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// `n` random lowercase letters and digits, the first a letter.
fn random_tag(n: usize, rng: &mut rand::rngs::OsRng) -> String {
    random_from(&LOWER_DIGITS[..26], 1, rng) + &random_from(LOWER_DIGITS, n.saturating_sub(1), rng)
}

/// A random username from the bundled word lists or random characters. Not a secret.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_username(options: UsernameOptions) -> Result<String> {
    use crate::words::{ADJECTIVES, NOUNS};
    let mut rng = rand::rngs::OsRng;
    match options.kind {
        UsernameKind::Words => {
            if !USERNAME_SEPARATORS.contains(&options.separator.as_str()) {
                return Err(PassError::InvalidInput(crate::i18n::tr!(
                    "generator.bad_separator"
                )));
            }
            let adjective = ADJECTIVES.choose(&mut rng).expect("non-empty");
            let noun = NOUNS.choose(&mut rng).expect("non-empty");
            let mut name = format!(
                "{}{}{}",
                capitalized(adjective, options.capitalize),
                options.separator,
                capitalized(noun, options.capitalize)
            );
            if options.include_number {
                name.push_str(&four_digits(&mut rng));
            }
            Ok(name)
        }
        UsernameKind::WordNumber => {
            let pool = if rng.gen_bool(0.5) { ADJECTIVES } else { NOUNS };
            let word = pool.choose(&mut rng).expect("non-empty");
            Ok(capitalized(word, options.capitalize) + &four_digits(&mut rng))
        }
        UsernameKind::Characters => {
            let length = options.length as usize;
            if !(4..=64).contains(&length) {
                return Err(PassError::InvalidInput(crate::i18n::tr!(
                    "generator.bad_length",
                    min = 4,
                    max = 64
                )));
            }
            Ok(random_tag(length, &mut rng))
        }
    }
}

/// What kind of e-mail address [`generate_email`] makes from the user's own address or domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum EmailKind {
    /// Plus addressing: `alex+k3vq9tmz@example.com` from `alex@example.com` (most providers
    /// deliver it to `alex@`).
    #[default]
    PlusAddress,
    /// A catch-all domain the user owns: `k3vq9tmz@mydomain.com`.
    CatchAll,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct EmailOptions {
    pub kind: EmailKind,
    /// `PlusAddress`: the user's own address.
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub address: String,
    /// `CatchAll`: the user's domain (`mydomain.com`; a leading `@` is fine).
    #[cfg_attr(feature = "uniffi", uniffi(default = ""))]
    pub domain: String,
    /// A website whose name becomes the tag instead of random characters.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub website: Option<String>,
}

/// Length of the random tag of a generated e-mail address.
const EMAIL_TAG_LEN: usize = 8;

/// The site's name for a tag: the first label of its registrable domain (`github` for
/// `https://www.github.com/login`), or `None` if nothing usable is left.
pub(crate) fn website_label(website: &str) -> Option<String> {
    let domain = crate::matching::registrable_domain(website.trim().to_string())?;
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let label: String = domain
        .split('.')
        .next()?
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(32)
        .collect::<String>()
        .to_ascii_lowercase();
    let label = label.trim_matches('-').to_string();
    (!label.is_empty() && !label.bytes().all(|b| b.is_ascii_digit())).then_some(label)
}

/// A domain name typed by the user: lowercase, a leading `@` and outer dots trimmed, labels of
/// `[a-z0-9-]`, at least two labels. `None` if it isn't one.
pub(crate) fn clean_domain(domain: &str) -> Option<String> {
    let d = domain
        .trim()
        .trim_start_matches('@')
        .trim_matches('.')
        .to_ascii_lowercase();
    let ok = d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    ok.then_some(d)
}

/// An e-mail address from the user's own address (plus addressing) or domain (catch-all), with a
/// random tag or the website's name.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_email(options: EmailOptions) -> Result<String> {
    let mut rng = rand::rngs::OsRng;
    let tag = options
        .website
        .as_deref()
        .and_then(website_label)
        .unwrap_or_else(|| random_tag(EMAIL_TAG_LEN, &mut rng));
    match options.kind {
        EmailKind::PlusAddress => {
            let bad = || PassError::InvalidInput(crate::i18n::tr!("generator.bad_email"));
            let (local, domain) = options.address.trim().rsplit_once('@').ok_or_else(bad)?;
            let domain = clean_domain(domain).ok_or_else(bad)?;
            // An address that already has a tag: replace it.
            let base = local.split('+').next().unwrap_or_default();
            if base.is_empty()
                || base.chars().any(|c| {
                    c.is_whitespace() || c.is_control() || matches!(c, '"' | '@' | '<' | '>')
                })
            {
                return Err(bad());
            }
            Ok(format!("{base}+{tag}@{domain}"))
        }
        EmailKind::CatchAll => {
            let domain = clean_domain(&options.domain)
                .ok_or_else(|| PassError::InvalidInput(crate::i18n::tr!("generator.bad_domain")))?;
            Ok(format!("{tag}@{domain}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_words_shape() {
        for _ in 0..200 {
            let name = generate_username(UsernameOptions::default()).unwrap();
            let (a, n) = name.split_once('-').unwrap();
            assert!(a.as_bytes()[0].is_ascii_uppercase(), "{name}");
            assert!(n.as_bytes()[0].is_ascii_uppercase(), "{name}");
            assert!(crate::words::ADJECTIVES.contains(&a.to_ascii_lowercase().as_str()));
            assert!(crate::words::NOUNS.contains(&n.to_ascii_lowercase().as_str()));
        }
        let name = generate_username(UsernameOptions {
            capitalize: false,
            include_number: true,
            separator: "_".into(),
            ..Default::default()
        })
        .unwrap();
        let (a, rest) = name.split_once('_').unwrap();
        assert!(a.bytes().all(|b| b.is_ascii_lowercase()));
        let (noun, digits) = rest.split_at(rest.len() - 4);
        assert!(digits.bytes().all(|b| b.is_ascii_digit()), "{name}");
        assert!(crate::words::NOUNS.contains(&noun));
        let joined = generate_username(UsernameOptions {
            separator: "".into(),
            ..Default::default()
        })
        .unwrap();
        assert!(joined.bytes().all(|b| b.is_ascii_alphabetic()));
        for bad in [" ", "/", "--", "@"] {
            assert!(generate_username(UsernameOptions {
                separator: bad.into(),
                ..Default::default()
            })
            .is_err());
        }
    }

    #[test]
    fn username_word_number_and_characters() {
        for _ in 0..100 {
            let name = generate_username(UsernameOptions {
                kind: UsernameKind::WordNumber,
                ..Default::default()
            })
            .unwrap();
            let (word, digits) = name.split_at(name.len() - 4);
            assert!(digits.bytes().all(|b| b.is_ascii_digit()));
            assert!(word.bytes().all(|b| b.is_ascii_alphabetic()) && word.len() >= 3);
            assert!(word.as_bytes()[0].is_ascii_uppercase());
        }
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..100 {
            let name = generate_username(UsernameOptions {
                kind: UsernameKind::Characters,
                length: 10,
                ..Default::default()
            })
            .unwrap();
            assert_eq!(name.len(), 10);
            assert!(name.as_bytes()[0].is_ascii_lowercase());
            assert!(name.bytes().all(|b| LOWER_DIGITS.contains(&b)));
            seen.insert(name);
        }
        // 26 * 36^9 possibilities: 100 draws don't repeat.
        assert_eq!(seen.len(), 100);
        for length in [3, 65] {
            assert!(generate_username(UsernameOptions {
                kind: UsernameKind::Characters,
                length,
                ..Default::default()
            })
            .is_err());
        }
    }

    #[test]
    fn plus_address_and_catch_all() {
        let plus = generate_email(EmailOptions {
            address: " Alex.Doe@Example.COM ".into(),
            ..Default::default()
        })
        .unwrap();
        let (local, domain) = plus.split_once('@').unwrap();
        assert_eq!(domain, "example.com");
        let (base, tag) = local.split_once('+').unwrap();
        assert_eq!(base, "Alex.Doe");
        assert_eq!(tag.len(), EMAIL_TAG_LEN);
        assert!(tag.bytes().all(|b| LOWER_DIGITS.contains(&b)));
        // An existing tag is replaced; the website names the tag.
        assert_eq!(
            generate_email(EmailOptions {
                address: "alex+old@example.com".into(),
                website: Some("https://accounts.github.com/login".into()),
                ..Default::default()
            })
            .unwrap(),
            "alex+github@example.com"
        );
        for bad in [
            "",
            "alex",
            "@example.com",
            "alex@",
            "alex@localhost",
            "a b@x.com",
            "+x@x.com",
            "a@b@x.com",
        ] {
            assert!(
                generate_email(EmailOptions {
                    address: bad.into(),
                    ..Default::default()
                })
                .is_err(),
                "{bad}"
            );
        }
        let catch_all = generate_email(EmailOptions {
            kind: EmailKind::CatchAll,
            domain: "@MyDomain.com".into(),
            ..Default::default()
        })
        .unwrap();
        let (tag, domain) = catch_all.split_once('@').unwrap();
        assert_eq!(domain, "mydomain.com");
        assert_eq!(tag.len(), EMAIL_TAG_LEN);
        assert_eq!(
            generate_email(EmailOptions {
                kind: EmailKind::CatchAll,
                domain: "mydomain.com".into(),
                website: Some("shop.example.co.uk".into()),
                ..Default::default()
            })
            .unwrap(),
            "example@mydomain.com"
        );
        // No usable site name: random.
        let ip = generate_email(EmailOptions {
            kind: EmailKind::CatchAll,
            domain: "mydomain.com".into(),
            website: Some("http://192.168.1.1".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ip.split_once('@').unwrap().0.len(), EMAIL_TAG_LEN);
        for bad in ["", "localhost", "a..b", "-a.com", "a b.com", "x@y.com"] {
            assert!(
                generate_email(EmailOptions {
                    kind: EmailKind::CatchAll,
                    domain: bad.into(),
                    ..Default::default()
                })
                .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn password_has_every_class() {
        for _ in 0..50 {
            let p = generate_password(PasswordOptions {
                length: 8,
                ..Default::default()
            })
            .unwrap();
            assert_eq!(p.chars().count(), 8);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| !c.is_ascii_alphanumeric()));
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
        let digits = generate_password(PasswordOptions {
            length: 6,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            avoid_ambiguous: false,
        })
        .unwrap();
        assert!(digits.chars().all(|c| c.is_ascii_digit()));
        assert!(generate_password(PasswordOptions {
            length: 2,
            ..Default::default()
        })
        .is_err());
    }

    fn passphrase_list() -> std::collections::HashSet<&'static str> {
        PASSPHRASE_WORDS.lines().collect()
    }

    #[test]
    fn passphrase_wordlist_is_the_eff_large_list() {
        assert_eq!(PASSPHRASE_WORDS.lines().count(), 7776);
        assert_eq!(passphrase_list().len(), 7776);
        assert!(PASSPHRASE_WORDS
            .lines()
            .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')));
    }

    #[test]
    fn passphrase_shape() {
        let list = passphrase_list();
        for _ in 0..200 {
            let p = generate_passphrase(6, "|".into());
            let parts: Vec<&str> = p.split('|').collect();
            assert_eq!(parts.len(), 6, "{p}");
            assert_eq!(p.chars().filter(|c| c.is_ascii_digit()).count(), 1, "{p}");
            let mut digit_words = 0;
            for part in parts {
                let word = part.trim_end_matches(|c: char| c.is_ascii_digit());
                digit_words += usize::from(word.len() != part.len());
                assert!(list.contains(word), "{word} is not on the list");
            }
            assert_eq!(digit_words, 1, "{p}");
        }
    }

    #[test]
    fn passphrase_word_count_is_kept_in_range() {
        assert_eq!(generate_passphrase(1, "|".into()).split('|').count(), 4);
        assert_eq!(generate_passphrase(99, "|".into()).split('|').count(), 20);
        assert!(!generate_passphrase(5, "".into()).contains('|'));
    }

    #[test]
    fn passphrase_picks_spread_over_the_whole_list() {
        let mut seen = std::collections::HashSet::new();
        let mut digit_slots = [0u32; 4];
        for _ in 0..5000 {
            let p = generate_passphrase(4, "|".into());
            for (i, part) in p.split('|').enumerate() {
                seen.insert(part.trim_end_matches(|c: char| c.is_ascii_digit()).to_string());
                if part.ends_with(|c: char| c.is_ascii_digit()) {
                    digit_slots[i] += 1;
                }
            }
        }
        // 20000 picks from 7776 words cover about 92 percent of the list.
        assert!(seen.len() > 6000, "only {} different words", seen.len());
        // The digit lands in each position about a quarter of the time (1250 of 5000).
        assert!(digit_slots.iter().all(|&n| (900..1600).contains(&n)), "{digit_slots:?}");
    }
}
