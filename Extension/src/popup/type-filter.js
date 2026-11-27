// Only kinds the agent's lists tell apart are offered: Favorites needs `items.favorite` and Notes needs `notes.list`.
import { ext } from '../shared/api.js';
import { t } from '../shared/i18n.js';

const STORE_KEY = 'popupTypeFilter';

const always = () => true;
const never = () => false;
const favorite = (entry) => !!entry?.favorite;

/**
 * kind -> label key, which logins pass (`login`), which of the cards and addresses lists show (`forms`),
 * whether the notes list shows (`notes`), which of their entries pass (`keep`), `only`: no logins show,
 * `browse`: the cards, addresses and notes show without a search, `needs`: what the agent must list for it.
 */
const KINDS = {
  all: { label: 'popupTypeAll', login: always, forms: ['cards', 'addresses'], keep: always },
  favorites: { label: 'popupTypeFavorites', login: favorite, forms: ['cards', 'addresses'], notes: true, keep: favorite,
    browse: true, needs: 'favorites' },
  logins: { label: 'popupTypeLogins', login: always, forms: [], keep: always },
  twofa: { label: 'commonBadge2fa', login: (i) => !!i?.has_totp, forms: [], keep: always },
  passkeys: { label: 'commonPasskey', login: (i) => !!i?.has_passkey, forms: [], keep: always },
  cards: { label: 'popupTypeCards', login: never, forms: ['cards'], keep: always, only: true, browse: true, needs: 'cards' },
  addresses: { label: 'popupTypeAddresses', login: never, forms: ['addresses'], keep: always, only: true, browse: true,
    needs: 'addresses' },
  notes: { label: 'popupTypeNotes', login: never, forms: [], notes: true, keep: always, only: true, browse: true, needs: 'notes' },
};

const NOTHING_OFFERED = Object.freeze({ cards: false, addresses: false, favorites: false, notes: false });

export function mountTypeFilter({ onChange }) {
  let selected = 'all';
  let offered = NOTHING_OFFERED;

  const available = (kind) => !KINDS[kind].needs || offered[KINDS[kind].needs];

  function choose(kind) {
    if (kind === selected) return;
    selected = kind;
    save();
    onChange();
  }

  function save() {
    try { Promise.resolve(ext.storage?.local?.set({ [STORE_KEY]: selected })).catch(() => {}); } catch { /* not kept */ }
  }

  // The kind kept from last time, before the first list is drawn.
  const ready = (async () => {
    try {
      const stored = (await ext.storage?.local?.get(STORE_KEY))?.[STORE_KEY];
      if (typeof stored === 'string' && Object.hasOwn(KINDS, stored)) selected = stored;
    } catch { /* All */ }
  })();

  return {
    ready,
    items() {
      return Object.entries(KINDS).filter(([kind]) => available(kind)).map(([kind, def]) => ({
        id: `type-${kind}`, label: t(def.label), selected: kind === selected, onSelect: () => choose(kind),
      }));
    },
    get label() { return selected === 'all' ? '' : t(KINDS[selected].label); },
    reset() {
      if (selected === 'all') return false;
      selected = 'all';
      save();
      return true;
    },
    update(next) {
      offered = { cards: !!next?.cards, addresses: !!next?.addresses, favorites: !!next?.favorites, notes: !!next?.notes };
      if (!available(selected)) selected = 'all';
    },
    matches(item) {
      return KINDS[selected].login(item);
    },
    matchesRow(li) {
      return KINDS[selected].login({ has_totp: !!li.dataset.totp, has_passkey: !!li.dataset.passkey, favorite: !!li.dataset.favorite });
    },
    showsForms(kind) {
      return KINDS[selected].forms.includes(kind);
    },
    keeps(entry) {
      return KINDS[selected].keep(entry);
    },
    get showsNotes() { return !!KINDS[selected].notes; },
    get noLogins() { return !!KINDS[selected].only; },
    get formsOnly() { return !!KINDS[selected].only && KINDS[selected].forms.length > 0; },
    get browses() { return !!KINDS[selected].browse; },
    get active() { return selected !== 'all'; },
  };
}
