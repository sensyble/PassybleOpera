//! Which items the AI tools connector (`passyble-mcp`) may offer to Claude Code, Codex or another
//! MCP client, and whether each use asks first. The mark is a custom field ([`AI_ACCESS_FIELD`]),
//! not a new item key, because every client keeps custom fields through edits, syncs and merges.
//! Imports strip it, so an export file can't share an item.

use crate::model::{CustomField, FieldKind, Item};

/// The name of the custom field that marks an item "Available to AI tools". Fixed English, as it
/// is data in the vault, not UI text.
pub const AI_ACCESS_FIELD: &str = "Passyble: available to AI tools";

/// The field's value for [`AiAccess::Ask`].
const ASK_VALUE: &str = "Ask every time";
/// The field's value for [`AiAccess::Allow`].
const ALLOW_VALUE: &str = "Allow without asking";

/// How an item shared with AI tools may be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum AiAccess {
    /// Every use asks the user (the default), unless they allowed it until the vault locks.
    Ask,
    /// Commands may get it without a prompt while the vault is unlocked (each use is logged).
    /// Revealing the value to the AI still asks every time.
    Allow,
}

impl AiAccess {
    /// The value stored in the field.
    pub fn as_value(self) -> &'static str {
        match self {
            AiAccess::Ask => ASK_VALUE,
            AiAccess::Allow => ALLOW_VALUE,
        }
    }

    /// `ask` or `allow` (protocol and settings).
    pub fn as_str(self) -> &'static str {
        match self {
            AiAccess::Ask => "ask",
            AiAccess::Allow => "allow",
        }
    }

    /// Reads a field value, as typed in any client: "Allow without asking" (any case and
    /// spacing) is [`AiAccess::Allow`]; an empty value, `no`, `off`, `false`, `0` or "not shared"
    /// is not shared (`None`); anything else is [`AiAccess::Ask`], the safe choice.
    pub fn from_value(value: &str) -> Option<AiAccess> {
        let words = value.split_whitespace().collect::<Vec<_>>().join(" ");
        let norm = words.to_lowercase();
        match norm.as_str() {
            "" | "no" | "off" | "false" | "0" | "not shared" => None,
            "allow without asking" | "allow" => Some(AiAccess::Allow),
            _ => Some(AiAccess::Ask),
        }
    }
}

/// Whether `field` is the "Available to AI tools" mark (name compared without case and
/// surrounding spaces).
pub fn is_ai_access_field(field: &CustomField) -> bool {
    field.name.trim().eq_ignore_ascii_case(AI_ACCESS_FIELD)
}

impl Item {
    /// Whether (and how) the item is shared with AI tools: the first mark field decides. Items in
    /// the trash are never shared.
    pub fn ai_access(&self) -> Option<AiAccess> {
        if self.is_trashed() {
            return None;
        }
        self.fields
            .iter()
            .find(|f| is_ai_access_field(f))
            .and_then(|f| AiAccess::from_value(&f.value))
    }

    /// Shares the item with AI tools (`Some`) or stops sharing it (`None`). Replaces every mark
    /// field with one at the end of the custom fields; the other fields keep their order.
    pub fn set_ai_access(&mut self, access: Option<AiAccess>) {
        self.fields.retain(|f| !is_ai_access_field(f));
        if let Some(access) = access {
            self.fields.push(CustomField {
                name: AI_ACCESS_FIELD.to_string(),
                value: access.as_value().to_string(),
                kind: FieldKind::Text,
            });
        }
    }
}

/// [`Item::ai_access`] for the apps (UniFFI).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn item_ai_access(item: Item) -> Option<AiAccess> {
    item.ai_access()
}

/// [`Item::set_ai_access`] for the apps (UniFFI): the item with the mark set or removed.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn item_with_ai_access(item: Item, access: Option<AiAccess>) -> Item {
    let mut item = item;
    item.set_ai_access(access);
    item
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_read_safely() {
        assert_eq!(AiAccess::from_value("Ask every time"), Some(AiAccess::Ask));
        assert_eq!(
            AiAccess::from_value("  allow   WITHOUT asking "),
            Some(AiAccess::Allow)
        );
        assert_eq!(AiAccess::from_value("allow"), Some(AiAccess::Allow));
        assert_eq!(AiAccess::from_value("yes please"), Some(AiAccess::Ask));
        for off in ["", "  ", "No", "off", "FALSE", "0", "not shared"] {
            assert_eq!(AiAccess::from_value(off), None, "{off:?}");
        }
        for a in [AiAccess::Ask, AiAccess::Allow] {
            assert_eq!(AiAccess::from_value(a.as_value()), Some(a));
        }
    }

    #[test]
    fn set_and_read() {
        let mut item = Item {
            fields: vec![CustomField {
                name: "PIN".into(),
                value: "1".into(),
                kind: FieldKind::Hidden,
            }],
            ..Default::default()
        };
        assert_eq!(item.ai_access(), None);
        item.set_ai_access(Some(AiAccess::Ask));
        item.set_ai_access(Some(AiAccess::Allow));
        assert_eq!(item.ai_access(), Some(AiAccess::Allow));
        assert_eq!(item.fields.len(), 2);
        assert_eq!(item.fields[0].name, "PIN");
        assert_eq!(item.fields[1].kind, FieldKind::Text);
        // A mark typed by hand in another client counts too.
        item.fields[1].name = " passyble: AVAILABLE to ai tools ".into();
        assert_eq!(item.ai_access(), Some(AiAccess::Allow));
        item.trashed_at = Some(1);
        assert_eq!(item.ai_access(), None);
        item.trashed_at = None;
        item.set_ai_access(None);
        assert_eq!(item.ai_access(), None);
        assert_eq!(item.fields.len(), 1);
        let back = item_with_ai_access(item.clone(), Some(AiAccess::Ask));
        assert_eq!(item_ai_access(back), Some(AiAccess::Ask));
    }
}
