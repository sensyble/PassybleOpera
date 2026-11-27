// The setup checklist as a pure function of what the page observed (no DOM, no browser API).
// An agent_unavailable error means Passyble is not running or has no vault yet: the app starts its
// agent only once it has a vault.
import { isHostMissing } from '../shared/messages.js';

/** `obs.agent`: the last `popup.status` outcome (null: not asked yet). `current` marks the first step not done. */
export function setupSteps(obs = {}) {
  const { agent = null, accessNeeded = false, access = true, pinned = false } = obs;
  const status = agent && 'status' in agent ? agent.status || {} : null;
  const error = agent?.error || null;
  const hostMissing = !!error && isHostMissing(error);
  const unavailable = !!error && !hostMissing && error.code === 'agent_unavailable';
  const steps = [
    { id: 'install', done: !!agent && !hostMissing, detail: hostMissing ? 'missing' : '' },
    { id: 'start', done: !!status || (!!error && !hostMissing && !unavailable), detail: unavailable ? 'stopped' : '' },
    { id: 'vault', done: !!status, detail: status ? (status.locked ? 'locked' : 'unlocked') : '' },
  ];
  if (accessNeeded) steps.push({ id: 'access', done: !!access, detail: '' });
  steps.push({ id: 'pin', done: !!pinned, detail: '' });
  const first = steps.find((s) => !s.done);
  for (const s of steps) s.current = s === first;
  return { steps, allDone: !first, checking: !agent };
}

/** Which part the setup guide starts with: 'app', 'choice', 'create', 'open', 'drive' or 'ready'. An installed Passyble app always wins. */
export function vaultStart(info, hash = '') {
  if (!info?.supported || info.app_installed === true) return 'app';
  if (['sync', 'drive', 'move'].includes(hash)) return 'drive';
  if (info.mode === 'browser' && info.has_vault) return 'ready';
  const asked = ['browser', 'create', 'open'].includes(hash);
  if (info.mode === 'browser' || asked || (!info.mode && info.host === 'missing') || info.app_gone === true) {
    return hash === 'create' || hash === 'open' ? hash : 'choice';
  }
  return 'app';
}
