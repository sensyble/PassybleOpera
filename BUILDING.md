# Building Passyble for Opera 0.1.3 from source

The extension is plain JavaScript (no bundler, no minifier): every .js file in pass-opera.zip is the
file in Extension/src/ as is. The only generated files are the browser vault's WebAssembly in src/wasm/:

| file | made from |
|---|---|
| src/wasm/pass_wasm_bg.wasm, src/wasm/pass_wasm.js | the Rust crate Core/wasm (pass-wasm), with wasm-bindgen |
| src/wasm/pass_wasm_kdf.wasm | the Rust crate Core/wasm/kdf (pass-wasm-kdf) |
| src/wasm/kdf.js | copied from Core/wasm/kdf/kdf.js |

Tools used for this package:

* rustc 1.99.0 (b940084d7 2026-09-28)
* cargo 1.99.0 (5f94df478 2026-08-27)
* rustup target wasm32-unknown-unknown
* wasm-bindgen-cli 0.2.129 (`cargo install wasm-bindgen-cli --version 0.2.129 --locked`)
* Node.js v26.2.0
* no wasm-opt

Steps (Linux, macOS or Windows):

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
cd Extension
node scripts/build-wasm.mjs --no-install --no-opt
node scripts/package-opera.mjs --out out
```

`Extension/out/pass-opera.zip` is then the extension. To compare with the uploaded file, unzip both and
compare them. build-wasm.mjs maps local paths (the Cargo home and the Core folder) to fixed names, so
the WebAssembly comes out the same wherever it is built, and the zip has fixed timestamps and sorted
entries. Every file should match byte for byte.

The extension talks to the Passyble desktop app over native messaging (com.sensyble.pass), or keeps its
own encrypted vault in the browser (the WebAssembly above).
