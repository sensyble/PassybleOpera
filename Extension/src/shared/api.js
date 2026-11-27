// Firefox exposes promise-based `browser.*`; Chromium MV3 exposes promise-based `chrome.*`.
export const ext = globalThis.browser ?? globalThis.chrome;

/** True when running in Firefox (or another Gecko browser). */
export const isGecko = typeof globalThis.browser !== 'undefined' &&
  typeof globalThis.browser.runtime?.getBrowserInfo === 'function';
