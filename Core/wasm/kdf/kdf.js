// Argon2id in a short-lived WebAssembly instance. A WebAssembly memory never shrinks, and Argon2id
// with the vault defaults grows it by 64 MiB, so each run gets a fresh instance that is zeroed and
// dropped afterwards.
//
//   setKdf(await loadKdf(new URL('./pass_wasm_kdf.wasm', import.meta.url)));

/**
 * Compiles the Argon2id module once and returns `argon2id(secret, salt, mKib, t, p)`, which gives
 * the 32-byte key as a Uint8Array (throws if Argon2 refuses the parameters).
 * @param {URL | string | ArrayBuffer | ArrayBufferView | WebAssembly.Module} source
 */
export async function loadKdf(source) {
  let module;
  if (source instanceof WebAssembly.Module) {
    module = source;
  } else if (source instanceof ArrayBuffer || ArrayBuffer.isView(source)) {
    module = await WebAssembly.compile(source);
  } else {
    const response = await fetch(source);
    if (!response.ok) throw new Error(`pass_wasm_kdf.wasm: HTTP ${response.status}`);
    module = await WebAssembly.compile(await response.arrayBuffer());
  }
  return function argon2id(secret, salt, mKib, t, p) {
    const { exports } = new WebAssembly.Instance(module, {});
    const { memory, kdf_alloc: alloc, kdf_argon2id: run } = exports;
    let bytes = null;
    try {
      const secretAt = alloc(secret.length);
      const saltAt = alloc(salt.length);
      const outAt = alloc(32);
      bytes = new Uint8Array(memory.buffer);
      bytes.set(secret, secretAt);
      bytes.set(salt, saltAt);
      const status = run(secretAt, secret.length, saltAt, salt.length, mKib, t, p, outAt);
      // The memory grew, so take a new view over the new buffer.
      bytes = new Uint8Array(memory.buffer);
      if (status !== 0) throw new Error('Argon2id refused the parameters');
      return bytes.slice(outAt, outAt + 32);
    } finally {
      // Leave no secret, key or Argon2 block behind in the dropped instance.
      new Uint8Array(memory.buffer).fill(0);
    }
  };
}
