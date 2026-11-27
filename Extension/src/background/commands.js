// The keyboard shortcuts the background handles. Scan QR and new note open the popup and hand it the action
// once (takePopupAction), so the screenshot stays in the popup's memory. `openPopup` is called before anything
// is awaited: Firefox allows it only while the key press is being handled. Below the minimum version nothing
// fills, generates, locks or syncs.

export const POPUP_ACTION_TTL_MS = 60_000;

const POPUP_ACTIONS = Object.freeze({ 'scan-qr': 'scan', 'new-note': 'note' });

export function createCommands({ ext, isWebUrl, blocked, sendToFillFrame, notify, lock, generate, copy, sync, syncText, t,
  errorText, now = Date.now }) {
  let popupAction = null;

  async function activeTab(tab) {
    if (tab?.id !== undefined) return tab;
    try {
      return (await ext.tabs.query({ active: true, currentWindow: true }))[0] || null;
    } catch {
      return null;
    }
  }

  const say = (tab, text) => (tab && isWebUrl(tab.url) ? notify(tab.id, text).catch(() => {}) : Promise.resolve());

  /** Opens the popup for `action`; synchronous up to `openPopup`. */
  function openPopupFor(action, tab) {
    popupAction = { action, tabId: tab?.id, at: now() };
    let opening;
    try {
      opening = typeof ext.action?.openPopup === 'function'
        ? Promise.resolve(ext.action.openPopup(typeof tab?.windowId === 'number' ? { windowId: tab.windowId } : undefined))
        : Promise.reject(new Error('no openPopup'));
    } catch (err) {
      opening = Promise.reject(err);
    }
    return opening.then(() => ({ opened: true }), async () => {
      const target = await activeTab(tab);
      if (popupAction && popupAction.tabId === undefined) popupAction.tabId = target?.id;
      await say(target, t('cmdUseToolbar'));
      return { opened: false };
    });
  }

  async function generatePassword(tab) {
    const target = await activeTab(tab);
    if (!target || await blocked()) return { done: false };
    const url = target.url || '';
    if (isWebUrl(url)) {
      try {
        const res = await sendToFillFrame(target.id, { type: 'cmd.generate-here', focused: true });
        if (res?.ok) return { done: 'filled' };
      } catch { /* no content script here: copied below */ }
    }
    const { password, byAgent } = await generate(isWebUrl(url) ? url : '');
    const res = await copy(password, byAgent);
    if (!res?.ok) {
      await say(target, t('cmdGenerateCopyFailed'));
      return { done: false };
    }
    await say(target, res.byApp ? t('cmdGeneratedCopiedByApp') : t('cmdGeneratedCopied'));
    return { done: 'copied' };
  }

  async function lockVault(tab) {
    if (await blocked()) return { done: false };
    const target = await activeTab(tab);
    try {
      await lock();
    } catch (err) {
      await say(target, errorText(err));
      return { done: false };
    }
    await say(target, t('cmdLocked'));
    return { done: 'locked' };
  }

  async function syncVaults(tab) {
    if (await blocked()) return { done: false };
    const target = await activeTab(tab);
    let outcome;
    try {
      outcome = { result: await sync() };
    } catch (err) {
      outcome = { error: err };
    }
    await say(target, syncText(outcome));
    return { done: outcome.error ? false : 'synced' };
  }

  async function fill(command, tab) {
    if (await blocked()) return { done: false };
    const target = await activeTab(tab);
    if (!target || !isWebUrl(target.url)) return { done: false };
    await sendToFillFrame(target.id, { type: command === 'fill-login' ? 'cmd.fill-login' : 'cmd.fill-otp' });
    return { done: 'sent' };
  }

  function handle(command, tab) {
    if (POPUP_ACTIONS[command]) return openPopupFor(POPUP_ACTIONS[command], tab);
    if (command === 'fill-login' || command === 'fill-otp') return fill(command, tab);
    if (command === 'generate-password') return generatePassword(tab);
    if (command === 'lock') return lockVault(tab);
    if (command === 'sync-now') return syncVaults(tab);
    return Promise.resolve({ done: false });
  }

  function takePopupAction(tabId) {
    const pending = popupAction;
    if (!pending) return null;
    if (now() - pending.at > POPUP_ACTION_TTL_MS) { popupAction = null; return null; }
    if (pending.tabId !== undefined && pending.tabId !== Number(tabId)) return null;
    popupAction = null;
    return pending.action;
  }

  return { handle, takePopupAction };
}
