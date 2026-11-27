// Stand-in for src/wasm/kdf.js: the fake vault needs no Argon2id.
export async function loadKdf() {
  return () => new Uint8Array(32);
}
