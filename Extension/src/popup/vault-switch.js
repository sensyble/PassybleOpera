// The extension never asks for the other vault's unlock: the desktop app does, and the open vault stays open until then.
// Team and Family vaults open with the personal vault, so they are no switch targets.
import { icon } from '../shared/svg-icon.js';
import { openMenu } from '../ui/popover.js';
import { friendlyError } from '../shared/messages.js';
import { t } from '../shared/i18n.js';
import { pinnedFirst } from '../shared/vaults.js';

const nameOf = (v) => v?.name || t('bannerMyVault');

function span(cls, text) {
  const node = document.createElement('span');
  node.className = cls;
  node.textContent = text;
  return node;
}

export function mountVaultSwitch(button, note, { send, snack, pins, pinOf = () => null }) {
  let own = []; // vaults.own: [{ id, vault_id, name, location, active }]
  let pending = null; // { id, name }: the desktop app waits for this vault's unlock
  let supported = true;

  function render() {
    const active = own.find((v) => v.active === true);
    button.hidden = own.length < 2 || !active;
    button.replaceChildren(span('vault-switch-name', nameOf(active)), icon('chevronDown', { size: 14 }));
    note.hidden = !pending;
    note.textContent = pending ? t('popupSwitchUnlockInApp', pending.name) : '';
  }

  async function switchTo(v) {
    try {
      if ((await send('popup.switch-vault', { id: v.id }))?.switching !== true) return;
      pending = { id: v.id, name: nameOf(v) };
      render();
    } catch (err) {
      snack(friendlyError(err));
    }
  }

  button.addEventListener('click', () => openMenu(button, pinnedFirst(own, pins(), 'vault_id', (v) => v.active === true).map((v) => ({
    label: nameOf(v), selected: v.active === true, onSelect: () => { if (!v.active) switchTo(v); }, pin: pinOf(v.vault_id, nameOf(v)),
  })), { label: t('popupSwitchVault') }));

  return {
    async refresh() {
      if (!supported) return;
      let res = null;
      try {
        res = await send('popup.own-vaults');
      } catch (err) {
        if (err?.code === 'not_supported') supported = false;
      }
      own = Array.isArray(res?.vaults) ? res.vaults.filter((v) => v && typeof v.id === 'string' && v.id) : [];
      if (pending && own.some((v) => v.active === true && v.id === pending.id)) pending = null;
      render();
    },
    hide() {
      own = [];
      pending = null;
      render();
    },
  };
}
