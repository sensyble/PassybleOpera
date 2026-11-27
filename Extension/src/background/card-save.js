// The "Save card" / "Update card expiry" banner after a checkout form with a card was submitted.
//
// The captured card (never the security code) is taken only from the top frame or a frame of the tab's own
// origin, as the browser reports them (a payment provider's cross-origin iframe is skipped), only on secure
// pages, and lives in memory for a few minutes. The agent compares numbers itself, so a saved number never
// comes to the browser, and the banner gets only the brand, last four digits and expiry. The edit frame and
// Save act by the banner's one-time token.
import { ErrorCode, PassError, Reason } from '../shared/errors.js';
import { isSecureFormUrl } from '../shared/cards.js';
import { cardBrand, cardMonth, cardYear, cleanHolder, cleanTitle, parseExpiry, validCardNumber } from '../shared/card-rules.js';
import { chosenVault, newLoginVaultChoice } from '../shared/vaults.js';

/** The banner shows within this time of the submit (3-D Secure steps can take a while). */
export const CARD_SHOW_MS = 3 * 60_000;
/** The captured card is dropped this long after the submit, whatever happens. */
export const CARD_KEEP_MS = 5 * 60_000;
export const CARD_EDIT_PATH = 'src/save/card-edit.html';

function safeOrigin(url) {
  try { return new URL(url).origin; } catch { return 'null'; }
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}

function nothing() {
  return new PassError(ErrorCode.NOT_FOUND, 'Nothing to save', Reason.NOTHING_TO_SAVE);
}

export function createCardSave(deps) {
  const now = deps.now || (() => Date.now());

  const drop = (s, card) => { if (s.card === card) s.card = null; };
  const fresh = (card, ms = CARD_KEEP_MS) => !!card && now() - card.at <= ms;

  async function supported() {
    try {
      return (await deps.agentFeatures({ automatic: true })).includes('cards.save');
    } catch {
      return false;
    }
  }

  function checkParams(card) {
    const params = { url: card.url, number: card.number };
    if (card.month && card.year) {
      params.expiry_month = card.month;
      params.expiry_year = card.year;
    }
    return params;
  }

  function target(card) {
    const e = card.edits;
    return {
      ...card,
      holder: e?.holder ?? card.holder,
      month: e ? e.month : card.month,
      year: e ? e.year : card.year,
      title: e?.title ?? '',
    };
  }

  /** While locked: whether the card may already be saved, from the soft lock's list (never a number). */
  async function mayBeSaved(card) {
    let res;
    try { res = await deps.agent('cards.list', { url: card.url }, { automatic: true }); } catch { return false; }
    if (res?.locked !== true || !Array.isArray(res.items)) return false;
    const last4 = card.number.slice(-4);
    return res.items.some((c) => c?.last4 === last4 &&
      (!card.month || (Number(c.expiry_month) === card.month && Number(c.expiry_year) === card.year)));
  }

  function bannerInfo(card, decided) {
    card.held = false;
    card.shown = true;
    card.decided = !!decided;
    card.action = decided?.action || 'save_new';
    card.id = card.action === 'update_expiry' ? decided.id ?? null : null;
    card.edits = null;
    card.vaultChoice = card.action === 'save_new' ? newLoginVaultChoice(decided) : null;
    const out = {
      mode: card.action === 'update_expiry' ? 'update' : 'save',
      host: hostOf(card.url),
      brand: typeof decided?.brand === 'string' && decided.brand ? decided.brand : card.brand,
      last4: card.number.slice(-4),
      expiry_month: card.month,
      expiry_year: card.year,
      token: card.token,
      editable: true,
    };
    if (out.mode === 'update') {
      out.title = typeof decided.title === 'string' ? decided.title.slice(0, 256) : null;
      const vault = decided.vault;
      if (vault && vault.home !== true && typeof vault.name === 'string') out.vault_name = vault.name.slice(0, 120);
    }
    if (card.vaultChoice) out.vaults = card.vaultChoice;
    return out;
  }

  function editFrameCard(msg, sender) {
    if (typeof sender.url !== 'string' || sender.url.split(/[?#]/)[0] !== deps.extensionUrl(CARD_EDIT_PATH)) return null;
    if (!sender.tab || typeof sender.tab.id !== 'number' || !(Number(sender.frameId) > 0)) return null;
    const card = deps.tabs.get(sender.tab.id)?.card;
    if (!card || !card.shown || typeof msg.token !== 'string' || msg.token !== card.token || !fresh(card)) return null;
    return card;
  }

  function byToken(s, msg) {
    const card = s.card;
    return card && typeof msg.token === 'string' && msg.token === card.token && fresh(card) ? card : null;
  }

  async function recheck(s) {
    const card = s.card;
    if (!awaitsUnlock(card)) return null;
    let decided;
    try { decided = await deps.agent('cards.save_check', checkParams(card), { automatic: true }); } catch { return null; }
    if (s.card !== card) return null;
    card.rechecked = true;
    if (decided?.action === 'none') {
      drop(s, card);
      return card.held ? null : { close: true };
    }
    if (!card.held) return null; // the banner on screen stays: its Save checks again
    if (await deps.isNeverSave(card.url)) { drop(s, card); return null; }
    return bannerInfo(card, decided);
  }

  function awaitsUnlock(card) {
    return !!card && !card.decided && !card.rechecked && (card.held || card.shown) && fresh(card);
  }

  const contentHandlers = {
    /** A submitted card form, kept only when it may be offered. */
    async 'card.capture'(msg, sender) {
      if (!sender.tab || typeof sender.tab.id !== 'number') return {};
      const url = deps.frameUrl(sender);
      if (!isSecureFormUrl(url)) return {};
      const top = sender.frameId === 0 || sender.frameId === undefined
        ? url
        : String(sender.tab.url || '');
      // A payment provider's cross-origin iframe: never offered, whatever its script sent.
      if (safeOrigin(top) !== safeOrigin(url)) return {};
      if (!(await deps.getSettings()).cardSave) return {};
      const number = validCardNumber(typeof msg.number === 'string' ? msg.number : '');
      if (!number) return {};
      let month = cardMonth(msg.expiry_month);
      let year = cardYear(String(msg.expiry_year ?? ''));
      if (!month || !year) month = year = 0;
      const s = deps.tabState(sender.tab.id);
      if (s.card && s.card.number === number && s.card.month === month && s.card.year === year && fresh(s.card)) {
        if (!s.card.holder) s.card.holder = cleanHolder(msg.cardholder_name);
        return {};
      }
      const card = {
        url, number, month, year, holder: cleanHolder(msg.cardholder_name), brand: cardBrand(number),
        at: now(), shown: false, token: globalThis.crypto.randomUUID(),
      };
      s.card = card;
      // Never keep a card number around longer than the banner could need it.
      const purge = setTimeout(() => drop(s, card), CARD_KEEP_MS);
      purge?.unref?.(); // Node (tests) only
      Promise.resolve(deps.sendToTop(sender.tab.id, { type: 'card.offer' })).catch(() => {});
      return {};
    },

    async 'card.query'(msg, sender) {
      if (sender.frameId !== 0) return null;
      const s = deps.tabState(sender.tab.id);
      if (msg?.recheck === true) return recheck(s);
      const card = s.card;
      if (!card || card.shown || card.held || !fresh(card, CARD_SHOW_MS)) return null;
      card.shown = true;
      if (!(await deps.getSettings()).cardSave || (await deps.isNeverSave(card.url)) || !(await supported())) {
        drop(s, card);
        return null;
      }
      let decided;
      try {
        decided = await deps.agent('cards.save_check', checkParams(card), { automatic: true });
      } catch (err) {
        if (PassError.from(err).code !== ErrorCode.LOCKED) { drop(s, card); return null; }
        // Locked: the agent can't compare numbers. Soft-locked with what may be this card: wait for
        // the unlock (recheckAll); otherwise offer it now (Save unlocks and checks again).
        if (await mayBeSaved(card)) { card.shown = false; card.held = true; return null; }
        decided = null;
      }
      if (s.card !== card) return null;
      if (decided?.action === 'none') { drop(s, card); return null; }
      return bannerInfo(card, decided);
    },

    /** Save / Update on the banner, by its one-time token. The card leaves memory whatever happens. */
    async 'card.commit'(msg, sender) {
      const s = deps.tabState(sender.tab.id);
      const card = byToken(s, msg);
      if (!card) throw nothing();
      drop(s, card);
      const t = target(card);
      const edited = !!card.edits && (t.month !== card.month || t.year !== card.year);
      let action = card.action;
      let id = card.id;
      if (!card.decided || edited) {
        const decided = await deps.withUnlock(() => deps.agent('cards.save_check', checkParams(t)));
        action = decided?.action || 'save_new';
        if (action === 'none') return { id: decided.id ?? null, unchanged: true, action };
        id = action === 'update_expiry' ? decided.id ?? null : null;
      }
      const params = checkParams(t);
      if (t.holder) params.cardholder_name = t.holder;
      if (id) {
        params.id = id;
      } else {
        if (t.title) params.title = t.title;
        const vault = chosenVault(card.vaultChoice, msg.vault);
        if (vault) params.vault = vault;
      }
      const res = await deps.withUnlock(() => deps.agent('cards.save', params));
      return {
        id: res?.id ?? null, title: typeof res?.title === 'string' ? res.title : null,
        unchanged: res?.unchanged === true, updated: res?.updated === true,
        action: res?.updated ? 'update_expiry' : action,
      };
    },

    /** "Never for this site": the origin comes from the browser's sender URL. */
    async 'card.never'(msg, sender) {
      if (sender.frameId !== 0) throw nothing();
      const s = deps.tabState(sender.tab.id);
      const card = s.card && typeof msg.token === 'string' && msg.token === s.card.token ? s.card : null;
      if (!card) throw nothing();
      drop(s, card);
      const site = await deps.addNeverSave(card.url);
      if (!site) throw new PassError(ErrorCode.NOT_FOUND, 'Passyble only works on http(s) pages', Reason.WEB_PAGES_ONLY);
      return { site };
    },

    async 'card.dismiss'(msg, sender) {
      const s = deps.tabState(sender.tab.id);
      if (!msg?.token || msg.token === s.card?.token) s.card = null;
      return {};
    },
  };

  const pageHandlers = {
    /** What the edit frame starts with. Never the number. */
    async 'card.edit-get'(msg, sender) {
      const card = editFrameCard(msg, sender);
      if (!card) throw nothing();
      card.edits = null;
      return {
        mode: card.action === 'update_expiry' ? 'update' : 'save',
        holder: card.holder, expiry_month: card.month, expiry_year: card.year,
        brand: card.brand || '', last4: card.number.slice(-4),
      };
    },

    async 'card.edit-set'(msg, sender) {
      const card = editFrameCard(msg, sender);
      if (!card) throw nothing();
      const holder = cleanHolder(typeof msg.holder === 'string' ? msg.holder : '');
      if (typeof msg.holder === 'string' && msg.holder.trim() && !holder) throw badParams('Bad name');
      const title = msg.title === undefined ? '' : cleanTitle(msg.title);
      if (title === null) throw badParams('Bad title');
      const expiry = typeof msg.expiry === 'string' ? msg.expiry.trim() : '';
      const parsed = expiry ? parseExpiry(expiry) : { month: 0, year: 0 };
      if (!parsed) throw badParams('Bad expiry');
      card.edits = { holder, month: parsed.month, year: parsed.year, title };
      return {};
    },
  };

  /** After an unlock, each tab whose card waits for it is asked to check again. */
  function recheckAll() {
    for (const [tabId, s] of deps.tabs) {
      if (!awaitsUnlock(s.card)) continue;
      Promise.resolve(deps.sendToTop(tabId, { type: 'card.offer', recheck: true })).catch(() => {});
    }
  }

  return { contentHandlers, pageHandlers, recheckAll };
}

function badParams(message) {
  return new PassError(ErrorCode.INVALID_PARAMS, message, Reason.BAD_REQUEST);
}
