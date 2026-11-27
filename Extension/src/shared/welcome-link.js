import { ext } from './api.js';

const WELCOME_PAGE = 'src/welcome/welcome.html';

/** The guide's URL inside the extension, optionally at `section`. */
export function welcomeUrl(section = '') {
  return ext.runtime.getURL(WELCOME_PAGE) + (section ? `#${section}` : '');
}

export function openWelcome(section = '') {
  return ext.tabs.create({ url: welcomeUrl(section) });
}
