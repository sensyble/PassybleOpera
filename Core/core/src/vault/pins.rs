//! Pinned vaults: kept at the top of every vault list and as quick filters over the item list.
//! Stored in the home vault's settings under `ui.pinned_vaults` as a JSON array of vault ids, so
//! the pins follow the user to every device.
//! The app drops ids of vaults the user can no longer see before it saves.

use super::{PassError, Result, Vault};
use crate::i18n::tr;

const PINS_SETTING: &str = "ui.pinned_vaults";
/// The most vaults that can be pinned.
pub const MAX_PINNED_VAULTS: usize = 5;
const MAX_VAULT_ID_LEN: usize = 128;

fn valid_vault_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_VAULT_ID_LEN
        && !id.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Vault {
    /// The pinned vault ids in pin order (empty when none are pinned). An id may name a vault this
    /// device doesn't know: skip it when showing the pins.
    pub fn pinned_vaults(&self) -> Vec<String> {
        let ids: Vec<String> = self
            .setting(PINS_SETTING)
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default();
        let mut out: Vec<String> = Vec::new();
        for id in ids {
            if valid_vault_id(&id) && !out.contains(&id) {
                out.push(id);
            }
        }
        out
    }

    /// Saves the pins in this order (duplicates dropped, an empty list removes the setting) and
    /// returns what was saved. `InvalidInput` for an id that can't be a vault's, or for more than
    /// [`MAX_PINNED_VAULTS`]. Save the vault afterwards, as after an edit.
    pub fn set_pinned_vaults(&self, ids: Vec<String>) -> Result<Vec<String>> {
        let mut pins: Vec<String> = Vec::new();
        for id in ids {
            let id = id.trim().to_string();
            if !valid_vault_id(&id) {
                return Err(PassError::InvalidInput(tr!("settings.bad_vault_id")));
            }
            if !pins.contains(&id) {
                pins.push(id);
            }
        }
        if pins.len() > MAX_PINNED_VAULTS {
            return Err(PassError::InvalidInput(tr!(
                "settings.too_many_pins",
                max = MAX_PINNED_VAULTS
            )));
        }
        let value = if pins.is_empty() {
            None
        } else {
            Some(
                serde_json::to_string(&pins)
                    .map_err(|_| PassError::Crypto(tr!("error.internal")))?,
            )
        };
        self.put_setting(PINS_SETTING, value)?;
        Ok(pins)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn vault(device: &str) -> Arc<Vault> {
        Vault::create_with_kdf(
            "pw",
            device,
            crate::KdfParams {
                m_kib: 64,
                t: 1,
                p: 1,
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pins_keep_order_and_drop_duplicates() {
        let v = vault("laptop");
        assert!(v.pinned_vaults().is_empty());
        let saved = v.set_pinned_vaults(ids(&["b", " a ", "b"])).unwrap();
        assert_eq!(saved, ids(&["b", "a"]));
        assert_eq!(v.pinned_vaults(), ids(&["b", "a"]));
        assert_eq!(v.setting(PINS_SETTING).as_deref(), Some(r#"["b","a"]"#));
        v.set_pinned_vaults(Vec::new()).unwrap();
        assert!(v.setting(PINS_SETTING).is_none());
    }

    #[test]
    fn pins_refuse_bad_ids_and_a_sixth() {
        let v = vault("laptop");
        assert!(v.set_pinned_vaults(ids(&["a b"])).is_err());
        assert!(v.set_pinned_vaults(ids(&[""])).is_err());
        assert!(v
            .set_pinned_vaults(ids(&["1", "2", "3", "4", "5", "6"]))
            .is_err());
        assert!(v.pinned_vaults().is_empty());
        v.set_pinned_vaults(ids(&["1", "2", "3", "4", "5"]))
            .unwrap();
        assert_eq!(v.pinned_vaults().len(), MAX_PINNED_VAULTS);
    }

    #[test]
    fn pins_read_what_other_clients_wrote() {
        let v = vault("phone");
        v.put_setting(PINS_SETTING, Some(r#"["x","x",""," y",7]"#.into()))
            .unwrap();
        // Not an array of strings: nothing pinned rather than a guess.
        assert!(v.pinned_vaults().is_empty());
        v.put_setting(PINS_SETTING, Some(r#"["x","x","","bad id"]"#.into()))
            .unwrap();
        assert_eq!(v.pinned_vaults(), ids(&["x"]));
    }

    #[test]
    fn pins_sync_with_the_vault() {
        let laptop = vault("laptop");
        let phone =
            Vault::unlock(laptop.serialize().unwrap(), "pw".into(), "phone".into()).unwrap();
        phone.set_pinned_vaults(ids(&["team-1"])).unwrap();
        laptop.merge_remote(phone.serialize().unwrap()).unwrap();
        assert_eq!(laptop.pinned_vaults(), ids(&["team-1"]));
    }
}
