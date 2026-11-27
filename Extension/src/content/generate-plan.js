// The in-page generator's plan for one field: the user's options fitted to what the field allows
// (password-rules.js). A passphrase that can't fit becomes a password; each forced change adds a note.
import {
  generatePassword, generatePassphrase, passwordStrength, passphraseStrength, PASSPHRASE_MIN_WORDS,
} from '../shared/generator.js';
import { fitLength } from './password-rules.js';

/** A field taking fewer characters than this gets a password even when a passphrase is asked for. */
export const PASSPHRASE_MIN_CHARS = 20;
/** Passphrases tried per word count before one fits the field's length limits. */
const PASSPHRASE_TRIES = 40;

/** { mode, length, lowercase, uppercase, digits, symbols, words, notes }; `notes`: [{ key, count? }] in card order. */
export function planFor(options, limits = {}, symbols = true) {
  const notes = [];
  const plan = { ...options, symbols: symbols !== false, notes };
  if (limits.symbols === false) {
    plan.symbols = false;
    notes.push({ key: 'genNoteNoSymbols' });
  }
  if (plan.mode === 'passphrase' && limits.maxLength && limits.maxLength < PASSPHRASE_MIN_CHARS) {
    plan.mode = 'password';
    notes.push({ key: 'genNotePassphraseTooLong' });
  }
  if (plan.mode === 'password') {
    const length = fitLength(options.length, limits);
    if (length > options.length) notes.push({ key: 'genNoteMinLength', count: length });
    else if (length < options.length) notes.push({ key: 'genNoteMaxLength', count: length });
    plan.length = length;
    if (!plan.lowercase && !plan.uppercase && !plan.digits && !plan.symbols) {
      Object.assign(plan, { lowercase: true, uppercase: true, digits: true });
      notes.push({ key: 'genNoteLettersDigits' });
    }
  } else {
    if (limits.maxLength) notes.push({ key: 'genNoteMaxLength', count: limits.maxLength });
    if (limits.minLength) notes.push({ key: 'genNoteMinLength', count: limits.minLength });
  }
  return plan;
}

/** True when the desktop app's `generate` (length and symbols only) makes what `plan` asks for. */
export function agentCanMake(plan) {
  return plan.mode === 'password' && plan.lowercase && plan.uppercase && plan.digits;
}

function fits(value, limits) {
  const n = [...value].length;
  return (!limits.minLength || n >= limits.minLength) && (!limits.maxLength || n <= limits.maxLength);
}

/** Makes what `plan` asks for here (`words`: the passphrase wordlist). Returns { password, mode, words?, notes }. */
export function makeLocally(plan, limits = {}, { words = null, rng } = {}) {
  const notes = [...plan.notes];
  const random = rng ? { rng } : {};
  if (plan.mode === 'passphrase' && words?.length) {
    const counts = [];
    for (let n = plan.words; n >= PASSPHRASE_MIN_WORDS; n--) counts.push(n);
    for (let n = plan.words + 1; n <= plan.words + 4; n++) counts.push(n);
    for (const n of counts) {
      for (let i = 0; i < PASSPHRASE_TRIES; i++) {
        const password = generatePassphrase(words, { words: n, plain: !plan.symbols, ...random });
        if (fits(password, limits)) return { password, mode: 'passphrase', words: n, notes };
      }
    }
    notes.push({ key: 'genNotePassphraseTooLong' });
  }
  const length = plan.mode === 'password' ? plan.length : fitLength(plan.length, limits);
  const password = generatePassword({
    length, lowercase: plan.lowercase, uppercase: plan.uppercase, digits: plan.digits, symbols: plan.symbols, ...random,
  });
  return { password, mode: 'password', notes };
}

/** Strength for the preview: a passphrase by its words, a password by its characters. */
export function strengthOf(result) {
  return result.mode === 'passphrase' ? passphraseStrength(result.password, result.words) : passwordStrength(result.password);
}
