// Pins are the agent's (`vaults.pins` / `vaults.set_pins`) and are sent back whole, so pins of vaults this browser
// doesn't show stay.
import { friendlyError } from '../shared/messages.js';
import { t } from '../shared/i18n.js';
import { pinnedFirst, pinsOf, togglePin } from '../shared/vaults.js';

/** The name of a vault as the popup shows it: the home vault without a name of its own is "Personal". */
export function vaultName(v) {
  return v?.name || (v?.home ? t('bannerMyVault') : '');
}

export function mountVaultFilter({ send, snack, onChange, onPins = () => {}, known = () => [] }) {
  let vaults = new Map();
  let pins = null; // { pins, max } of vaults.pins; null: no pins (an older agent, or locked)
  let selected = '';

  function choose(id) {
    if (id === selected) return;
    selected = id;
    onChange();
  }

  async function setPin(id, on) {
    if (!pins) return;
    const ids = togglePin(pins, id, on);
    if (!ids) { snack(t('popupPinLimit', pins.max)); return; }
    try {
      const shared = known();
      pins = pinsOf(await send('popup.set-pins', { ids, ...(shared.length ? { known: shared } : {}) }));
    } catch (err) {
      if (err?.code === 'not_supported') pins = null;
      snack(friendlyError(err));
    }
    onPins();
  }

  function pinOf(id, name) {
    if (!pins || !id) return null;
    const pinned = pins.pins.includes(id);
    return { pinned, label: t(pinned ? 'popupUnpinNamed' : 'popupPinNamed', name), menuLabel: t(pinned ? 'popupUnpinVault' : 'popupPinVault'),
      state: t('popupVaultPinned'), onToggle: () => setPin(id, !pinned) };
  }

  return {
    get offered() { return vaults.size >= 2; },
    items() {
      if (vaults.size < 2) return [];
      const ordered = pinnedFirst([...vaults.values()], pins?.pins, 'id', (v) => !!v.home);
      return [
        { id: 'vault-all', label: t('popupAllVaults'), selected: !selected, onSelect: () => choose('') },
        ...ordered.map((v) => ({ id: `vault-${v.id}`, label: vaultName(v), selected: v.id === selected, onSelect: () => choose(v.id),
          pin: pinOf(v.id, vaultName(v)) })),
      ];
    },
    get label() { return selected ? vaultName(vaults.get(selected)) : ''; },
    reset() {
      if (!selected) return false;
      selected = '';
      return true;
    },
    update(table, nextPins) {
      vaults = table instanceof Map ? table : new Map();
      pins = nextPins;
      const dropped = selected && !vaults.has(selected);
      if (dropped) selected = '';
      onPins();
      if (dropped) onChange();
    },
    matches(vaultId) {
      return !selected || vaultId === selected;
    },
    get selected() { return vaults.get(selected) || null; },
    get pins() { return pins?.pins || []; },
    pinOf,
  };
}
