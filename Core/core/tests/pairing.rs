//! Pairing link parsing against the shared test vectors.

use pass_core::{parse_pairing_link, parse_server_link, PassError};
use serde_json::Value;

const VECTORS: &str = include_str!("pairing_vectors.json");

#[test]
fn shared_vectors() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 10);
    for v in vectors {
        let link = v["link"].as_str().unwrap();
        let parsed = parse_pairing_link(link);
        let server = parse_server_link(link);
        match (&v["expect"], &v["signin"]) {
            (Value::Null, Value::Null) => {
                assert!(
                    matches!(server, Err(PassError::InvalidInput(_))),
                    "{link} must be rejected by parse_server_link, got {server:?}"
                );
            }
            (Value::Null, s) => {
                assert!(parsed.is_err(), "{link} is not a pairing link");
                let l = server.unwrap_or_else(|err| panic!("{link}: {err}"));
                assert!(l.pairing.is_none(), "{link}");
                assert_eq!(l.server_url, s["server_url"].as_str().unwrap(), "{link}");
                assert_eq!(l.host, s["host"].as_str().unwrap(), "{link}");
                assert_eq!(l.username, s["username"].as_str().unwrap(), "{link}");
                let pins: Vec<&str> = s["pins"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| p.as_str().unwrap())
                    .collect();
                assert_eq!(l.pins, pins, "{link}");
                assert_eq!(l.https, s["https"].as_bool().unwrap(), "{link}");
                match &s["code"] {
                    Value::Null => assert!(l.code.is_none() && l.code_kind.is_none(), "{link}"),
                    c => {
                        assert_eq!(l.code_kind.as_deref(), c[0].as_str(), "{link}");
                        assert_eq!(l.code.as_deref(), c[1].as_str(), "{link}");
                    }
                }
            }
            (_, _) => {
                let l = server.unwrap_or_else(|err| panic!("{link}: {err}"));
                assert_eq!(l.pairing.as_ref(), parsed.as_ref().ok(), "{link}");
            }
        }
        match &v["expect"] {
            Value::Null => assert!(
                matches!(parsed, Err(PassError::InvalidInput(_))),
                "{link} must be rejected, got {parsed:?}"
            ),
            e => {
                let p = parsed.unwrap_or_else(|err| panic!("{link}: {err}"));
                assert_eq!(p.url, e["url"].as_str().unwrap(), "{link}");
                assert_eq!(p.host, e["host"].as_str().unwrap(), "{link}");
                assert_eq!(p.username, e["username"].as_str().unwrap(), "{link}");
                assert_eq!(p.token, e["token"].as_str().unwrap(), "{link}");
                assert_eq!(
                    p.device_name.as_deref(),
                    e["device_name"].as_str(),
                    "{link}"
                );
                let pins: Vec<&str> = e["pins"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| p.as_str().unwrap())
                    .collect();
                assert_eq!(p.pins, pins, "{link}");
                assert_eq!(p.https, e["https"].as_bool().unwrap(), "{link}");
                #[cfg(feature = "webdav")]
                {
                    let c = pass_core::pairing_webdav_config(p.clone());
                    assert_eq!(
                        (c.url, c.username, c.password, c.pins),
                        (p.url, p.username, p.token, p.pins)
                    );
                }
            }
        }
    }
}
