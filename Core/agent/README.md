# pass-agent

The vault process of the Passyble password manager. It holds the unlocked vault, locks it after
inactivity, saves and syncs the vault file, and answers requests from the browser extension. It has
no GUI: the host supplies one through the `Ui` trait.

## How it is used

* **Desktop app.** The app runs an `Agent` and serves it over a named pipe on Windows
  (`\\.\pipe\pass-agent-<user>`) or a 0600 Unix socket elsewhere (`ipc::Server`). The browser
  extension reaches it through `pass-native-host`, the native messaging host.
* **Browser extension.** Without the `native` feature the same request handlers build for
  `wasm32-unknown-unknown`. The extension's own vault (`pass-wasm`) runs them on an `AgentHost`:
  a `store::MemoryStore` for the vault files, a `clock::Clock`, and `Timers::Host`, where the host
  calls `Agent::tick` when `Agent::next_tick` says.

## Security model

Every item request is checked against the requesting page's URL, so a page can't ask for another
site's login by id; passkey requests also check the origin and RP ID, and set the UV flag only after
a real user verification. On Windows the pipe server only accepts the native host and the app
installed beside it, and the native host only talks to a pipe served by that app, so another program
can't pose as either side. Secrets are never logged, and requests from AI tools (`ai.*`) are accepted
only from the `passyble-mcp` connector and see only items the user marked for AI tools.

## Features

| feature | default | adds |
|---|---|---|
| `native` | on | Local IPC, the vault file on disk (`store::FileStore`), process hardening (`harden`), the Windows passkey provider and `Agent::new`. |
| `webdav`, `gdrive` | on | Sync over WebDAV or Google Drive (`Agent::sync`, `Agent::sync_gdrive`). |
| `import-qr` | on | `totp.from_image`: read a 2FA QR code from an image. |
| `icons` | on | `icons.get` from the app's icon cache. |

Besides the home vault, the agent can hold shared vaults (Teams, Family, direct shares) that the
user's Passyble account opens (`Agent::set_linked_vaults`). Requests see all open vaults and their
roles are enforced.

## Testing

```
cargo test -p pass-agent
```

The integration tests in `tests/` drive the agent through its JSON protocol. `tests/hosted.rs` runs
the WebAssembly host setup natively and checks that it answers like the desktop agent, and
`tests/harden.rs` checks process hardening on a real child process. `examples/e2e_agent.rs` is the
agent the browser end-to-end tests talk to.
