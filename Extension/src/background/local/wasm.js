// Loads the browser vault's WebAssembly the first time browser mode needs it (an MV3 service worker can't
// import() later, so the glue is parsed up front, but the module is fetched only on use). Each Argon2id run
// gets a fresh, small kdf instance, so its 64 MiB never stays in the long-lived module. The glue is read as a
// namespace so a build without some functions still loads instead of stopping the whole service worker.
import init, * as glue from '../../wasm/pass_wasm.js';
import { loadKdf } from '../../wasm/kdf.js';

let loading = null;

/** `{ BrowserAgent, checkMasterPassword, glue }` once compiled; a failure is retried on the next call. */
export function loadWasm(url) {
  loading ??= (async () => {
    const response = fetch(url('src/wasm/pass_wasm_bg.wasm'));
    response.catch(() => {}); // init() reports it
    await init({ module_or_path: response });
    glue.setKdf(await loadKdf(url('src/wasm/pass_wasm_kdf.wasm')));
    return { BrowserAgent: glue.BrowserAgent, checkMasterPassword: glue.checkMasterPassword, glue };
  })();
  loading.catch(() => { loading = null; });
  return loading;
}
