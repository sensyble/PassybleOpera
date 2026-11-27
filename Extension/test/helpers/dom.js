import { JSDOM } from 'jsdom';

export function makeDom(html, { url = 'https://example.com/login' } = {}) {
  const dom = new JSDOM(`<!doctype html><html><head></head><body>${html}</body></html>`, { url, pretendToBeVisual: true });
  return { dom, window: dom.window, document: dom.window.document };
}

/**
 * Dispatches `event` with isTrusted = true, like a real user action. jsdom's dispatchEvent() always
 * makes events untrusted (as browsers do), so this goes through jsdom's internal dispatch.
 */
export async function dispatchTrusted(target, event) {
  const { default: utils } = await import('jsdom/lib/jsdom/living/generated/utils.js');
  const impl = utils.implForWrapper(event);
  impl.isTrusted = true;
  return utils.implForWrapper(target)._dispatch(impl);
}
