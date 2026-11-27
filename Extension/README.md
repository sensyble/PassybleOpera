# Passyble extension

Manifest V3 extension for Chromium browsers (Opera, Opera GX, Chrome, Edge, Brave).

It runs in one of two modes, picked per browser profile:

- **With the desktop app.** The extension talks to the Passyble app over native messaging
  (`com.sensyble.pass`). The vault stays in the app; the extension only sees the item it is filling.
- **In the browser.** The vault lives in the extension's IndexedDB, encrypted with the master password.
  The vault code is the same Rust as the desktop app, compiled to WebAssembly (`src/wasm/`).

On its own the extension makes one kind of network request: a check every few hours for the minimum
supported version (a public list on account.passyble.com; nothing about you or your vault is sent). Signing in
to a Passyble account is optional.

## Layout

- `src/background.js`, `src/background/`: service worker, native messaging, the in-browser vault
- `src/content/`: field detection, the fill menu, save prompts, passkeys
- `src/popup/`, `src/options/`, `src/welcome/`, `src/unlock/`, `src/save/`: extension pages
- `src/shared/`: code used by more than one of the above
- `_locales/`: translations
- `test/`: unit tests (`node --test`)
- `scripts/`: WebAssembly build and packaging

## Development

```sh
npm install
npm test
```

Load it unpacked from `chrome://extensions` or `opera://extensions` with developer mode on. The background
script needs `src/wasm/`, so build that first (see `../BUILDING.md`).

Requires Chromium 111 or newer.
