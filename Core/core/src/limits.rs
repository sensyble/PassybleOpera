//! Caps on what one item holds, so an item can't swell a vault. Counted in characters (Unicode
//! scalar values), not bytes. `Vault::upsert` checks them; an item already over a cap (saved by an
//! older client) still opens, syncs and saves, as long as the edit doesn't make it bigger there.

use crate::i18n::tr;
use crate::model::Item;
use crate::{PassError, Result};

/// Most characters in an item's notes.
pub const MAX_NOTES_CHARS: usize = 20_000;
/// Most characters in a custom field's value.
pub const MAX_FIELD_VALUE_CHARS: usize = 5_000;
/// Most characters in a custom field's name.
pub const MAX_FIELD_NAME_CHARS: usize = 500;
/// Most custom fields per item.
pub const MAX_ITEM_FIELDS: usize = 100;
/// Most websites per item.
pub const MAX_ITEM_URLS: usize = 100;

fn chars(s: &str) -> usize {
    s.chars().count()
}

/// Whether `notes` may replace `before` (the stored notes, `None` for a new item): at most
/// [`MAX_NOTES_CHARS`] characters, or no longer than `before`. `InvalidInput` with
/// "Notes can be up to 20,000 characters." otherwise. Callers that build notes (adding a line to
/// a note) check the result here before asking the user anything.
pub fn check_notes_length(notes: &str, before: Option<&str>) -> Result<()> {
    let n = chars(notes);
    if n <= MAX_NOTES_CHARS || before.is_some_and(|b| n <= chars(b)) {
        Ok(())
    } else {
        Err(PassError::InvalidInput(tr!("limits.notes")))
    }
}

/// The caps for `item` replacing `prev` (the stored copy, `None` for a new item).
pub(crate) fn check_item(item: &Item, prev: Option<&Item>) -> Result<()> {
    check_notes_length(&item.notes, prev.map(|p| p.notes.as_str()))?;
    let grew = |now: usize, max: usize, before: Option<usize>| now > max && before.is_none_or(|b| now > b);
    if grew(item.fields.len(), MAX_ITEM_FIELDS, prev.map(|p| p.fields.len())) {
        return Err(PassError::InvalidInput(tr!("limits.fields")));
    }
    if grew(item.urls.len(), MAX_ITEM_URLS, prev.map(|p| p.urls.len())) {
        return Err(PassError::InvalidInput(tr!("limits.urls")));
    }
    // A field over a cap is fine only with a value (or name) the stored copy has already.
    let had = |pick: fn(&crate::CustomField) -> &str, v: &str| {
        prev.is_some_and(|p| p.fields.iter().any(|f| pick(f) == v))
    };
    for f in &item.fields {
        if chars(&f.value) > MAX_FIELD_VALUE_CHARS && !had(|f| &f.value, &f.value) {
            return Err(PassError::InvalidInput(tr!("limits.field_value")));
        }
        if chars(&f.name) > MAX_FIELD_NAME_CHARS && !had(|f| &f.name, &f.name) {
            return Err(PassError::InvalidInput(tr!("limits.field_name")));
        }
    }
    Ok(())
}

/// Cuts `notes` to `max` characters; whether it was longer.
pub(crate) fn truncate_chars(notes: &mut String, max: usize) -> bool {
    match notes.char_indices().nth(max) {
        Some((at, _)) => {
            notes.truncate(at);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CustomField, Vault};
    use std::sync::Arc;

    fn vault() -> Arc<Vault> {
        let kdf = crate::KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..Default::default()
        };
        Vault::create_with_kdf("pw", "dev", kdf).unwrap()
    }

    fn note(text: &str) -> Item {
        Item {
            kind: crate::ItemKind::Note,
            title: "Note".into(),
            notes: text.into(),
            ..Default::default()
        }
    }

    fn is_cap(e: PassError, key: &str) -> bool {
        matches!(&e, PassError::InvalidInput(m) if *m == crate::i18n::text(key, &[]))
    }

    #[test]
    fn notes_message_names_the_cap() {
        assert_eq!(tr!("limits.notes"), "Notes can be up to 20,000 characters.");
    }

    #[test]
    fn new_item_notes_up_to_the_cap() {
        let v = vault();
        v.upsert(note(&"a".repeat(MAX_NOTES_CHARS))).unwrap();
        let e = v.upsert(note(&"a".repeat(MAX_NOTES_CHARS + 1))).unwrap_err();
        assert!(is_cap(e, "limits.notes"));
    }

    #[test]
    fn counts_characters_not_bytes() {
        let v = vault();
        let wide = "é".repeat(MAX_NOTES_CHARS);
        assert!(wide.len() > MAX_NOTES_CHARS);
        v.upsert(note(&wide)).unwrap();
        assert!(v.upsert(note(&format!("{wide}é"))).is_err());
    }

    #[test]
    fn update_within_and_past_the_cap() {
        let v = vault();
        let mut saved = v.upsert(note("short")).unwrap();
        saved.notes = "b".repeat(MAX_NOTES_CHARS);
        let mut saved = v.upsert(saved).unwrap();
        saved.notes.push('c');
        assert!(is_cap(v.upsert(saved.clone()).unwrap_err(), "limits.notes"));
        assert_eq!(v.get(saved.id.clone()).unwrap().notes.chars().count(), MAX_NOTES_CHARS);
    }

    /// An item stored over the cap (an older client, an import merge) still saves; it may shrink
    /// or stay, not grow.
    #[test]
    fn existing_note_over_the_cap_can_shrink_not_grow() {
        let v = vault();
        let big = "x".repeat(MAX_NOTES_CHARS + 500);
        let saved = v.upsert_with(note(&big), true).unwrap();
        let mut same = v.get(saved.id.clone()).unwrap();
        same.title = "Renamed".into();
        let same = v.upsert(same).unwrap();
        assert_eq!(same.notes, big);
        let mut grown = same.clone();
        grown.notes.push('y');
        assert!(is_cap(v.upsert(grown).unwrap_err(), "limits.notes"));
        let mut shrunk = same.clone();
        shrunk.notes.truncate(MAX_NOTES_CHARS + 100);
        let shrunk = v.upsert(shrunk).unwrap();
        let mut regrown = shrunk;
        regrown.notes.push_str(&"z".repeat(200));
        assert!(v.upsert(regrown).is_err());
    }

    /// The hook for adding a line to a note: same cap, nothing changed when refused.
    #[test]
    fn appending_respects_the_cap() {
        let near = "n".repeat(MAX_NOTES_CHARS - 3);
        assert!(check_notes_length(&format!("{near}\nab"), Some(&near)).is_ok());
        let e = check_notes_length(&format!("{near}\nabc"), Some(&near)).unwrap_err();
        assert!(is_cap(e, "limits.notes"));
        let v = vault();
        let saved = v.upsert(note(&near)).unwrap();
        let mut appended = saved.clone();
        appended.notes = format!("{near}\nabc");
        assert!(v.upsert(appended).is_err());
        assert_eq!(v.get(saved.id).unwrap().notes, near);
    }

    fn field(name: &str, value: &str) -> CustomField {
        CustomField {
            name: name.into(),
            value: value.into(),
            kind: Default::default(),
        }
    }

    #[test]
    fn custom_fields_and_websites_are_capped() {
        let v = vault();
        let mut item = note("");
        item.fields = vec![field("Q", &"v".repeat(MAX_FIELD_VALUE_CHARS))];
        let mut saved = v.upsert(item).unwrap();
        saved.fields[0].value.push('v');
        assert!(is_cap(v.upsert(saved.clone()).unwrap_err(), "limits.field_value"));
        saved.fields[0] = field(&"n".repeat(MAX_FIELD_NAME_CHARS + 1), "v");
        assert!(is_cap(v.upsert(saved.clone()).unwrap_err(), "limits.field_name"));
        saved.fields = (0..=MAX_ITEM_FIELDS).map(|i| field(&i.to_string(), "v")).collect();
        assert!(is_cap(v.upsert(saved.clone()).unwrap_err(), "limits.fields"));
        saved.fields.clear();
        saved.urls = (0..=MAX_ITEM_URLS).map(|i| format!("https://s{i}.example")).collect();
        assert!(is_cap(v.upsert(saved).unwrap_err(), "limits.urls"));
    }

    #[test]
    fn stored_fields_over_the_cap_still_save() {
        let v = vault();
        let mut item = note("");
        item.fields = (0..MAX_ITEM_FIELDS + 5).map(|i| field(&i.to_string(), "v")).collect();
        item.fields[0].value = "v".repeat(MAX_FIELD_VALUE_CHARS + 10);
        item.urls = (0..MAX_ITEM_URLS + 5).map(|i| format!("https://s{i}.example")).collect();
        let saved = v.upsert_with(item, true).unwrap();
        let mut edited = v.get(saved.id).unwrap();
        edited.title = "Edited".into();
        edited.fields.pop();
        edited.urls.pop();
        v.upsert(edited.clone()).unwrap();
        edited.urls.push("https://more.example".into());
        edited.urls.push("https://again.example".into());
        assert!(v.upsert(edited).is_err());
    }

    #[test]
    fn import_cuts_long_notes_and_says_which() {
        let long = "l".repeat(MAX_NOTES_CHARS + 50);
        let csv = format!(
            "name,url,username,password,note
Big,https://big.example,u,p,{long}
             Small,https://small.example,u,p,hi
"
        );
        let batch = crate::import_parse(csv.into_bytes(), "c.csv".into(), None).unwrap();
        let warning = tr!("import.notes_truncated", entries = "Big");
        assert!(batch.preview(vault()).warnings.contains(&warning));
        let v = vault();
        assert_eq!(batch.commit(v.clone()).unwrap().added, 2);
        let items = v.items();
        let big = items.iter().find(|i| i.title == "Big").unwrap();
        assert_eq!(big.notes, "l".repeat(MAX_NOTES_CHARS));
        assert_eq!(items.iter().find(|i| i.title == "Small").unwrap().notes, "hi");
    }

    /// An import merging into a stored item doesn't grow its notes past the cap.
    #[test]
    fn import_merge_keeps_notes_within_the_cap() {
        let v = vault();
        let mut login = note(&"s".repeat(MAX_NOTES_CHARS - 10));
        login.kind = crate::ItemKind::Login;
        login.title = "Site".into();
        login.username = "u".into();
        login.password = "p".into();
        login.urls = vec!["https://site.example".into()];
        v.upsert(login).unwrap();
        let csv = format!(
            "name,url,username,password,note
Site,https://site.example,u,p,{}
",
            "m".repeat(100)
        );
        let batch = crate::import_parse(csv.into_bytes(), "c.csv".into(), None).unwrap();
        batch.commit(v.clone()).unwrap();
        let items = v.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].notes.chars().count(), MAX_NOTES_CHARS);
    }

    #[test]
    fn truncate_cuts_at_a_character() {
        let mut s = "é".repeat(MAX_NOTES_CHARS + 2);
        assert!(truncate_chars(&mut s, MAX_NOTES_CHARS));
        assert_eq!(s.chars().count(), MAX_NOTES_CHARS);
        let mut short = "ok".to_string();
        assert!(!truncate_chars(&mut short, MAX_NOTES_CHARS));
        assert_eq!(short, "ok");
    }
}
