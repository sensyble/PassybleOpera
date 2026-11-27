//! Pinned vaults (`vaults.pins`, `vaults.set_pins`; the desktop app's own vault lists): kept in
//! the home vault (`Vault::pinned_vaults`), so they follow the user to every device.

use std::collections::HashSet;

use pass_core::{PassError, MAX_PINNED_VAULTS};

use crate::Agent;

impl Agent {
    /// The pinned vault ids in pin order, as saved: an id this device doesn't know is still in
    /// it (the caller skips it). `InvalidPassword` while locked.
    pub fn pinned_vaults(&self) -> Result<Vec<String>, PassError> {
        Ok(self
            .peek_vault()
            .ok_or(PassError::InvalidPassword)?
            .pinned_vaults())
    }

    /// Saves `ids` as the pins, in this order, dropping ids of vaults the user can't see. Earlier
    /// pins of shared vaults not opened yet are kept up to [`MAX_PINNED_VAULTS`]; more known ids
    /// than that is `InvalidInput`. Returns the pins saved.
    pub fn set_pinned_vaults(&self, ids: Vec<String>) -> Result<Vec<String>, PassError> {
        self.set_pinned_vaults_with(ids, Vec::new())
    }

    /// [`Agent::set_pinned_vaults`], with `also_known` vaults the caller can see.
    pub(crate) fn set_pinned_vaults_with(
        &self,
        ids: Vec<String>,
        also_known: Vec<String>,
    ) -> Result<Vec<String>, PassError> {
        let home = self.peek_vault().ok_or(PassError::InvalidPassword)?;
        let saved = home.pinned_vaults();
        let linked = self.linked_status();
        let unsure = linked.iter().any(|s| s.vault.is_none());
        let mut known: HashSet<String> = self
            .open_vaults()
            .into_iter()
            .map(|(r, _)| r.id)
            .chain(linked.into_iter().filter_map(|s| s.vault.map(|r| r.id)))
            .collect();
        known.extend(
            self.ui
                .own_vaults()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.vault_id)
                .chain(also_known),
        );
        let mut seen = HashSet::new();
        let mut pins: Vec<String> = ids
            .into_iter()
            .map(|id| id.trim().to_string())
            .filter(|id| seen.insert(id.clone()))
            .filter(|id| known.contains(id) || (unsure && saved.contains(id)))
            .collect();
        // Over the limit: the pins this device can't show go first.
        while pins.len() > MAX_PINNED_VAULTS {
            match pins.iter().rposition(|id| !known.contains(id)) {
                Some(i) => {
                    pins.remove(i);
                }
                None => break,
            }
        }
        let pins = home.set_pinned_vaults(pins)?;
        self.save()?;
        self.ui.vault_changed();
        Ok(pins)
    }
}
