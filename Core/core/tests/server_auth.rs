//! Server account password derivation against the shared test vectors.

use pass_core::{server_auth_key, ServerKdf};
use serde_json::Value;

const VECTORS: &str = include_str!("server_auth_vectors.json");

#[test]
fn shared_vectors() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 3);
    for v in vectors {
        let kdf: ServerKdf = ServerKdf {
            alg: v["kdf"]["alg"].as_str().unwrap().into(),
            m_kib: v["kdf"]["m_kib"].as_u64().unwrap() as u32,
            t: v["kdf"]["t"].as_u64().unwrap() as u32,
            p: v["kdf"]["p"].as_u64().unwrap() as u32,
        };
        let auth = server_auth_key(
            v["password"].as_str().unwrap().into(),
            v["salt"].as_str().unwrap().into(),
            kdf,
        )
        .unwrap();
        assert_eq!(auth, v["auth_key"].as_str().unwrap(), "{}", v["password"]);
    }
}
