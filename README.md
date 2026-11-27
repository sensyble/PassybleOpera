# Passyble for Opera

This is the source of the Passyble extension for Opera and Opera GX, as published on Opera Add-ons.

Passyble is a password manager. The extension fills logins, 2FA codes, passkeys, cards and addresses. It
works with the Passyble desktop app on the same computer, or keeps its own encrypted vault in the browser
if you don't have the app.

- Website: https://passyble.com
- Privacy policy: https://passyble.com/privacy/
- Help: https://passyble.com/guides/

## Layout

- `Extension/` is the extension itself. Plain JavaScript modules, nothing is bundled or minified.
- `Core/` holds the Rust crates that the in-browser vault is compiled from (`Extension/src/wasm/`).
- `Firefox/` has two packaging scripts and a manifest file the build imports.
- `BUILDING.md` lists the tool versions and the commands to rebuild the package.

## Releases

Every [release](https://github.com/sensyble/PassybleOpera/releases) matches a version on Opera Add-ons:

- `pass-opera.zip` is the extension package that was uploaded to Opera.
- `pass-opera-source.zip` is this repository at that version.

To try a release without the store, unzip `pass-opera.zip`, open `opera://extensions`, turn on developer
mode and pick "Load unpacked". It won't update itself; the copy from Opera Add-ons does.

## License

AGPL-3.0-or-later, see [LICENSE](LICENSE). Third-party code and fonts are listed in
[Extension/THIRD_PARTY_NOTICES.md](Extension/THIRD_PARTY_NOTICES.md).

Copyright Sensyble LLC.
