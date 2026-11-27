//! Embeds `locales/<tag>.json` as `CATALOGS: &[(&str, &str)]` (language tag, JSON text) for
//! `src/i18n.rs`. A language is added by adding its file.

fn main() {
    // Read when the script runs, not baked in when it was compiled: a shared target folder reuses
    // a compiled build script across checkouts, and `env!` would keep the first checkout's path.
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR");
    let dir = std::path::Path::new(&manifest).join("locales");
    println!("cargo:rerun-if-changed=locales");
    let mut entries: Vec<(String, std::path::PathBuf)> = std::fs::read_dir(&dir)
        .map(|d| {
            d.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .filter_map(|p| Some((p.file_stem()?.to_str()?.to_string(), p)))
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    assert!(
        entries.iter().any(|(code, _)| code == "en"),
        "Core/core/locales/en.json (the source catalog) is missing"
    );
    let mut out = String::from("const CATALOGS: &[(&str, &str)] = &[\n");
    for (code, _) in &entries {
        let rel = format!("locales/{code}.json");
        println!("cargo:rerun-if-changed={rel}");
        out.push_str(&format!(
            "    ({code:?}, include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{rel}\"))),\n"
        ));
    }
    out.push_str("];\n");
    let target =
        std::path::Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("core_catalogs.rs");
    std::fs::write(target, out).expect("write core_catalogs.rs");
}
