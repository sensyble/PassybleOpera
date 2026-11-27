//! Encrypted exports of other apps: right and wrong passwords, damaged data and key derivation
//! settings beyond the bounds. The files are built here, so no fixture is committed.

use std::io::{Cursor, Write};

use base64::Engine;
use serde_json::{json, Value};

use super::encrypted::testing;
use super::*;

const SECRET: &str = "JBSWY3DPEHPK3PXP";

fn open(data: &[u8], name: &str, password: &str) -> Result<ImportReport> {
    parse_import_with_password(data, name, password, None)
}

fn titles(r: &ImportReport) -> Vec<&str> {
    r.items.iter().map(|i| i.title.as_str()).collect()
}

fn find<'a>(r: &'a ImportReport, title: &str) -> &'a Item {
    r.items
        .iter()
        .find(|i| i.title == title)
        .unwrap_or_else(|| panic!("no item {title} in {:?}", titles(r)))
}

fn message(e: PassError) -> String {
    short_error(&e)
}

fn bitwarden_plain() -> String {
    json!({"encrypted": false, "folders": [{"id": "f1", "name": "Work"}], "items": [
        {"type": 1, "name": "Mail", "folderId": "f1", "login": {"username": "ann", "password": "bw-pass",
            "uris": [{"uri": "https://mail.example"}], "totp": SECRET}},
        {"type": 2, "name": "Note", "notes": "hello", "secureNote": {"type": 0}}
    ]})
    .to_string()
}

fn pbkdf2_kdf() -> Value {
    json!({"kdfType": 0, "kdfIterations": 1000})
}

// ---- Bitwarden --------------------------------------------------------------------------------

#[test]
fn bitwarden_password_protected_pbkdf2() {
    let file = testing::bitwarden(&bitwarden_plain(), "file pw", pbkdf2_kdf());
    let info = import_encryption(file.clone().into_bytes(), "bw.json".into()).unwrap();
    assert_eq!(info.format, Some(ImportFormat::BitwardenJson));
    assert!(!info.key_file);

    let r = open(file.as_bytes(), "bw.json", "file pw").unwrap();
    assert_eq!(r.format, ImportFormat::BitwardenJson);
    assert_eq!(titles(&r), ["Mail", "Note"]);
    let mail = find(&r, "Mail");
    assert_eq!(mail.password, "bw-pass");
    assert_eq!(mail.tags, ["Work"]);
    assert!(mail.totp.is_some());

    assert_eq!(
        open(file.as_bytes(), "bw.json", "wrong").unwrap_err(),
        PassError::InvalidPassword
    );
    let err = parse_import(file.as_bytes(), "bw.json", None).unwrap_err();
    assert!(message(err).contains("encrypted"));
    let batch = import_parse_with_password(
        file.clone().into_bytes(),
        "bw.json".into(),
        "file pw".into(),
    )
    .unwrap();
    assert_eq!(batch.item_count(), 2);
}

#[test]
fn bitwarden_password_protected_argon2id() {
    let kdf = json!({"kdfType": 1, "kdfIterations": 2, "kdfMemory": 1, "kdfParallelism": 1});
    let file = testing::bitwarden(&bitwarden_plain(), "pw", kdf);
    let r = open(file.as_bytes(), "bw.json", "pw").unwrap();
    assert_eq!(r.items.len(), 2);
    assert_eq!(
        open(file.as_bytes(), "bw.json", "pW").unwrap_err(),
        PassError::InvalidPassword
    );
}

#[test]
fn bitwarden_account_restricted_is_explained() {
    let file = json!({"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "2.AAAA|BBBB|CCCC",
        "folders": [], "items": [{"type": 1, "name": "2.enc|enc|enc"}]})
    .to_string();
    assert!(import_encryption(file.clone().into_bytes(), "x.json".into()).is_none());
    let err = open(file.as_bytes(), "x.json", "pw").unwrap_err();
    let text = message(err);
    assert!(
        text.contains("account") && text.contains("Password protected"),
        "{text}"
    );
    let err = parse_import(file.as_bytes(), "x.json", None).unwrap_err();
    assert!(message(err).contains("account"));
}

#[test]
fn bitwarden_damaged_and_heavy() {
    let file = testing::bitwarden(&bitwarden_plain(), "pw", pbkdf2_kdf());
    let mut v: Value = serde_json::from_str(&file).unwrap();

    // Altered data: the password is right (validation opens), the data's MAC fails.
    let data = v["data"].as_str().unwrap().to_string();
    let mut tampered = v.clone();
    let (head, mac) = data.rsplit_once('|').unwrap();
    let mut mac = base64::engine::general_purpose::STANDARD
        .decode(mac)
        .unwrap();
    mac[0] ^= 1;
    tampered["data"] = format!(
        "{head}|{}",
        base64::engine::general_purpose::STANDARD.encode(mac)
    )
    .into();
    let err = open(tampered.to_string().as_bytes(), "bw.json", "pw").unwrap_err();
    assert_ne!(err, PassError::InvalidPassword);
    assert!(message(err).contains("damaged"));

    // Garbage EncStrings.
    let mut garbage = v.clone();
    garbage["encKeyValidation_DO_NOT_EDIT"] = "not an enc string".into();
    assert!(
        message(open(garbage.to_string().as_bytes(), "bw.json", "pw").unwrap_err())
            .contains("damaged")
    );

    // Heavy settings are refused before anything is derived (this returns at once).
    v["kdfIterations"] = 50_000_000.into();
    let err = message(open(v.to_string().as_bytes(), "bw.json", "pw").unwrap_err());
    assert!(err.contains("unusually heavy"), "{err}");
    v["kdfType"] = 1.into();
    v["kdfIterations"] = 3.into();
    v["kdfMemory"] = 4096.into();
    v["kdfParallelism"] = 4.into();
    assert!(
        message(open(v.to_string().as_bytes(), "bw.json", "pw").unwrap_err())
            .contains("unusually heavy")
    );
    v["kdfType"] = 7.into();
    let unsupported = message(open(v.to_string().as_bytes(), "bw.json", "pw").unwrap_err());
    assert!(
        unsupported.contains("doesn't support") && !unsupported.contains("kdfType"),
        "{unsupported}"
    );
}

// ---- Aegis ------------------------------------------------------------------------------------

fn aegis_db() -> Value {
    json!({"version": 3, "entries": [
        {"type": "totp", "uuid": "1", "name": "ivan@example.com", "issuer": "GitHub", "note": "", "favorite": false,
         "info": {"secret": SECRET, "algo": "SHA1", "digits": 6, "period": 30}}
    ], "groups": []})
}

#[test]
fn aegis_encrypted_vault() {
    let file = testing::aegis(&aegis_db(), "aegis pw", 10);
    let info = import_encryption(file.clone().into_bytes(), "aegis.json".into()).unwrap();
    assert_eq!(info.format, Some(ImportFormat::Aegis));

    let r = open(file.as_bytes(), "aegis.json", "aegis pw").unwrap();
    assert_eq!(r.format, ImportFormat::Aegis);
    assert_eq!(titles(&r), ["GitHub"]);
    assert_eq!(r.items[0].username, "ivan@example.com");
    assert_eq!(
        open(file.as_bytes(), "aegis.json", "nope").unwrap_err(),
        PassError::InvalidPassword
    );

    let mut v: Value = serde_json::from_str(&file).unwrap();
    // Damaged vault: the master key opens, the db doesn't.
    let mut damaged = v.clone();
    let db = damaged["db"].as_str().unwrap().to_string();
    let flipped = if db.starts_with('A') { "B" } else { "A" };
    damaged["db"] = format!("{flipped}{}", &db[1..]).into();
    let err = open(damaged.to_string().as_bytes(), "aegis.json", "aegis pw").unwrap_err();
    assert!(message(err).contains("damaged"));

    // N = 2^22 with r = 8 would need 4 GiB.
    v["header"]["slots"][1]["n"] = (1u64 << 22).into();
    let err = message(open(v.to_string().as_bytes(), "aegis.json", "aegis pw").unwrap_err());
    assert!(err.contains("unusually heavy"), "{err}");

    let slots = v["header"]["slots"].as_array_mut().unwrap();
    slots.truncate(1);
    let err = message(open(v.to_string().as_bytes(), "aegis.json", "aegis pw").unwrap_err());
    assert!(err.contains("password slot"), "{err}");
}

// ---- 2FAS -------------------------------------------------------------------------------------

#[test]
fn twofas_encrypted_backup() {
    let services = json!([
        {"name": "Google", "secret": SECRET, "updatedAt": 1700000000000u64,
         "otp": {"label": "jane@gmail.com", "account": "jane@gmail.com", "issuer": "Google", "digits": 6, "period": 30,
                 "algorithm": "SHA1", "tokenType": "TOTP"}}
    ]);
    let file = testing::twofas(&services, "2fas pw");
    let info = import_encryption(file.clone().into_bytes(), "backup.2fas".into()).unwrap();
    assert_eq!(info.format, Some(ImportFormat::TwoFas));

    let r = open(file.as_bytes(), "backup.2fas", "2fas pw").unwrap();
    assert_eq!(r.format, ImportFormat::TwoFas);
    assert_eq!(titles(&r), ["Google"]);
    assert_eq!(
        open(file.as_bytes(), "backup.2fas", "2FAS pw").unwrap_err(),
        PassError::InvalidPassword
    );

    // The reference opens but the services were altered.
    let mut v: Value = serde_json::from_str(&file).unwrap();
    let enc = v["servicesEncrypted"].as_str().unwrap().to_string();
    let (ct, rest) = enc.split_once(':').unwrap();
    let mut bytes = encrypted::b64(ct).unwrap();
    bytes[0] ^= 1;
    v["servicesEncrypted"] = format!(
        "{}:{rest}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
    .into();
    let err = open(v.to_string().as_bytes(), "backup.2fas", "2fas pw").unwrap_err();
    assert!(message(err).contains("damaged"));
    v["servicesEncrypted"] = "garbage".into();
    assert!(open(v.to_string().as_bytes(), "backup.2fas", "2fas pw").is_err());
}

// ---- KeePass ----------------------------------------------------------------------------------

#[cfg(feature = "import-kdbx")]
mod keepass_tests {
    use keepass::config::{DatabaseConfig, KdfConfig};
    use keepass::db::Value as KpValue;
    use keepass::{Database, DatabaseKey};

    use super::*;

    /// A KDBX 4 database: entries in nested groups, the recycle bin, an attachment, TOTP fields.
    fn kdbx4(key: DatabaseKey, argon2: bool) -> Vec<u8> {
        let mut config = DatabaseConfig::default();
        if argon2 {
            // The default (Argon2d, 1 GiB, 50 passes) made light for the test.
            if let KdfConfig::Argon2 {
                iterations,
                memory,
                parallelism,
                ..
            } = &mut config.kdf_config
            {
                *iterations = 1;
                *memory = 1024 * 1024;
                *parallelism = 1;
            }
        } else {
            config.kdf_config = KdfConfig::Aes { rounds: 100 };
        }
        let mut db = Database::with_config(config);
        {
            let mut root = db.root_mut();
            root.name = "Root".into();
            let mut e = root.add_entry();
            e.set_unprotected("Title", "Mail");
            e.set_unprotected("UserName", "ann@example.com");
            e.set_protected("Password", "kp-pass");
            e.set_unprotected("URL", "https://mail.example");
            e.set_unprotected("KP2A_URL", "https://webmail.example");
            e.set_unprotected("Notes", "main account");
            e.set_unprotected(
                "otp",
                format!("otpauth://totp/Mail:ann?secret={SECRET}&period=30&digits=6"),
            );
            e.set_protected("PIN", "1234");
            e.set_unprotected("Recovery email", "ann@backup.example");
            e.tags.push("personal".into());
            e.add_attachment("scan.pdf", KpValue::unprotected(b"%PDF".to_vec()));
        }
        {
            let mut root = db.root_mut();
            let mut work = root.add_group();
            work.name = "Work".into();
            let mut clients = work.add_group();
            clients.name = "Clients".into();
            let mut e = clients.add_entry();
            e.set_unprotected("Title", "CRM");
            e.set_unprotected("UserName", "bob");
            e.set_protected("Password", "crm-pass");
            e.set_unprotected("TimeOtp-Secret-Base32", SECRET);
            e.set_unprotected("TimeOtp-Algorithm", "HMAC-SHA-256");
            e.set_unprotected("TimeOtp-Length", "8");
        }
        let bin_id = {
            let mut root = db.root_mut();
            let mut bin = root.add_group();
            bin.name = "Recycle Bin".into();
            let mut e = bin.add_entry();
            e.set_unprotected("Title", "Old");
            e.set_protected("Password", "old");
            bin.id()
        };
        db.meta.recyclebin_uuid = Some(bin_id.uuid());
        let mut out = Vec::new();
        db.save(&mut out, key).unwrap();
        out
    }

    fn check_items(r: &ImportReport) {
        assert_eq!(r.format, ImportFormat::Keepass);
        let mut t = titles(r);
        t.sort();
        assert_eq!(t, ["CRM", "Mail"]);
        let mail = find(r, "Mail");
        assert_eq!(mail.username, "ann@example.com");
        assert_eq!(mail.password, "kp-pass");
        assert_eq!(
            mail.urls,
            ["https://mail.example", "https://webmail.example"]
        );
        assert_eq!(mail.notes, "main account");
        assert!(mail.totp.as_deref().unwrap().contains(SECRET));
        assert_eq!(mail.tags, ["personal"]);
        let pin = mail.fields.iter().find(|f| f.name == "PIN").unwrap();
        assert_eq!((pin.value.as_str(), pin.kind), ("1234", FieldKind::Hidden));
        let recovery = mail
            .fields
            .iter()
            .find(|f| f.name == "Recovery email")
            .unwrap();
        assert_eq!(recovery.kind, FieldKind::Text);
        assert_eq!(mail.fields.len(), 2, "{:?}", mail.fields);
        let crm = find(r, "CRM");
        assert_eq!(crm.tags, ["Work/Clients"]);
        let cfg = crate::totp_parse(crm.totp.clone().unwrap()).unwrap();
        assert_eq!(cfg.digits, 8);
        assert_eq!(cfg.algorithm, crate::TotpAlgorithm::Sha256);
        assert!(crm.fields.is_empty(), "{:?}", crm.fields);
        assert_eq!(r.skipped.len(), 1, "the recycle bin entry");
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("Mail") && w.contains("scan.pdf")));
    }

    #[test]
    fn kdbx4_with_password() {
        let data = kdbx4(DatabaseKey::new().with_password("kp pw"), false);
        let info = import_encryption(data.clone(), "db.kdbx".into()).unwrap();
        assert_eq!(info.format, Some(ImportFormat::Keepass));
        assert!(info.key_file);
        check_items(&open(&data, "db.kdbx", "kp pw").unwrap());
        assert_eq!(
            open(&data, "db.kdbx", "kp PW").unwrap_err(),
            PassError::InvalidPassword
        );
        assert!(message(parse_import(&data, "db.kdbx", None).unwrap_err()).contains("KeePass"));
        assert!(message(open(&data, "db.kdbx", "").unwrap_err()).contains("password"));
        assert!(open(&data[..data.len() / 2], "db.kdbx", "kp pw").is_err());
    }

    #[test]
    fn kdbx4_argon2_with_key_file() {
        let key_file = b"<not xml, so the whole file is hashed> 0123456789".to_vec();
        let data = kdbx4(
            DatabaseKey::new()
                .with_password("kp pw")
                .with_keyfile(&mut &key_file[..])
                .unwrap(),
            true,
        );
        assert_eq!(
            open(&data, "db.kdbx", "kp pw").unwrap_err(),
            PassError::InvalidPassword
        );
        check_items(
            &parse_import_with_password(&data, "db.kdbx", "kp pw", Some(&key_file)).unwrap(),
        );
        let batch = import_parse_with_key_file(
            data.clone(),
            "db.kdbx".into(),
            "kp pw".into(),
            Some(key_file.clone()),
        )
        .unwrap();
        assert_eq!(batch.item_count(), 2);
        assert_eq!(
            parse_import_with_password(&data, "db.kdbx", "kp pw", Some(b"other")).unwrap_err(),
            PassError::InvalidPassword
        );

        // A key file alone.
        let data = kdbx4(
            DatabaseKey::new().with_keyfile(&mut &key_file[..]).unwrap(),
            false,
        );
        check_items(&parse_import_with_password(&data, "db.kdbx", "", Some(&key_file)).unwrap());
    }

    /// A KDBX 3.1 file as KeePass 2.x writes it: AES-256-CBC, AES-KDF, hashed block stream, no
    /// compression, no protected values.
    fn kdbx3(password: &str, rounds: u64, xml: &str) -> Vec<u8> {
        use aes::cipher::{
            block_padding::Pkcs7, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit,
        };
        use sha2::{Digest, Sha256};

        let master_seed = [1u8; 32];
        let transform_seed = [2u8; 32];
        let iv = [3u8; 16];
        let stream_start = [4u8; 32];
        let mut out = Vec::new();
        out.extend_from_slice(&[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&3u16.to_le_bytes());
        let mut field = |id: u8, data: &[u8]| {
            out.push(id);
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
            out.extend_from_slice(data);
        };
        field(
            2,
            &[
                0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc,
                0x5a, 0xff,
            ],
        );
        field(3, &0u32.to_le_bytes());
        field(4, &master_seed);
        field(5, &transform_seed);
        field(6, &rounds.to_le_bytes());
        field(7, &iv);
        field(8, &[5u8; 32]);
        field(9, &stream_start);
        field(10, &0u32.to_le_bytes());
        field(0, b"\r\n\r\n");

        let composite = Sha256::digest(Sha256::digest(password.as_bytes()));
        let aes = aes::Aes256::new_from_slice(&transform_seed).unwrap();
        let mut blocks = [
            aes::Block::clone_from_slice(&composite[..16]),
            aes::Block::clone_from_slice(&composite[16..]),
        ];
        for _ in 0..rounds {
            aes.encrypt_block(&mut blocks[0]);
            aes.encrypt_block(&mut blocks[1]);
        }
        let mut h = Sha256::new();
        h.update(blocks[0]);
        h.update(blocks[1]);
        let transformed = h.finalize();
        let mut h = Sha256::new();
        h.update(master_seed);
        h.update(transformed);
        let master_key = h.finalize();

        let mut payload = stream_start.to_vec();
        let body = xml.as_bytes();
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&Sha256::digest(body));
        payload.extend_from_slice(&(body.len() as u32).to_le_bytes());
        payload.extend_from_slice(body);
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&0u32.to_le_bytes());
        let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(&master_key, &iv)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(&payload);
        out.extend_from_slice(&ct);
        out
    }

    const KDBX3_XML: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta><Generator>KeePass</Generator><DatabaseName>Test</DatabaseName></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>Root</Name>
      <Entry>
        <UUID>AQAAAAAAAAAAAAAAAAAAAA==</UUID>
        <Times><CreationTime>2023-11-14T22:13:20Z</CreationTime><LastModificationTime>2024-01-01T00:00:00Z</LastModificationTime></Times>
        <String><Key>Title</Key><Value>Bank</Value></String>
        <String><Key>UserName</Key><Value>carol</Value></String>
        <String><Key>Password</Key><Value>bank-pass</Value></String>
        <String><Key>URL</Key><Value>https://bank.example</Value></String>
        <String><Key>TOTP Seed</Key><Value>JBSWY3DPEHPK3PXP</Value></String>
        <String><Key>TOTP Settings</Key><Value>30;6</Value></String>
      </Entry>
      <Group>
        <UUID>AgAAAAAAAAAAAAAAAAAAAA==</UUID>
        <Name>Email</Name>
        <Entry>
          <UUID>AwAAAAAAAAAAAAAAAAAAAA==</UUID>
          <String><Key>Title</Key><Value>Inbox</Value></String>
          <String><Key>UserName</Key><Value>carol@example.com</Value></String>
          <String><Key>Password</Key><Value>mail-pass</Value></String>
        </Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>"#;

    #[test]
    fn kdbx3_with_password() {
        let data = kdbx3("kp3", 1000, KDBX3_XML);
        assert!(
            import_encryption(data.clone(), "old.kdbx".into())
                .unwrap()
                .key_file
        );
        let r = open(&data, "old.kdbx", "kp3").unwrap();
        assert_eq!(r.format, ImportFormat::Keepass);
        let bank = find(&r, "Bank");
        assert_eq!(
            (bank.username.as_str(), bank.password.as_str()),
            ("carol", "bank-pass")
        );
        assert!(bank.totp.as_deref().unwrap().contains(SECRET));
        assert!(bank.fields.is_empty(), "{:?}", bank.fields);
        assert_eq!(bank.created_at, 1_700_000_000_000);
        assert_eq!(find(&r, "Inbox").tags, ["Email"]);
        assert_eq!(
            open(&data, "old.kdbx", "KP3").unwrap_err(),
            PassError::InvalidPassword
        );
    }

    #[test]
    fn kdbx_heavy_kdf_is_refused_before_deriving() {
        // KDBX 3.1 asking for 10^12 AES-KDF rounds (hours): refused at once.
        let mut header = vec![0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 3, 0];
        header.extend_from_slice(&[6, 8, 0]);
        header.extend_from_slice(&1_000_000_000_000u64.to_le_bytes());
        header.extend_from_slice(&[0, 4, 0, b'\r', b'\n', b'\r', b'\n']);
        let err = message(open(&header, "x.kdbx", "pw").unwrap_err());
        assert!(err.contains("unusually heavy"), "{err}");

        // KDBX 4 asking for Argon2 with 64 GiB.
        let mut dict = vec![0x00, 0x01];
        let mut entry = |kind: u8, name: &str, value: &[u8]| {
            dict.push(kind);
            dict.extend_from_slice(&(name.len() as i32).to_le_bytes());
            dict.extend_from_slice(name.as_bytes());
            dict.extend_from_slice(&(value.len() as i32).to_le_bytes());
            dict.extend_from_slice(value);
        };
        entry(
            0x42,
            "$UUID",
            &[
                0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0,
                0xa1, 0xe6,
            ],
        );
        entry(0x05, "M", &(64u64 << 30).to_le_bytes());
        entry(0x05, "I", &2u64.to_le_bytes());
        entry(0x04, "P", &2u32.to_le_bytes());
        dict.push(0);
        let mut header = vec![
            0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 4, 0, 11,
        ];
        header.extend_from_slice(&(dict.len() as u32).to_le_bytes());
        header.extend_from_slice(&dict);
        header.extend_from_slice(&[0, 4, 0, 0, 0, b'\r', b'\n', b'\r', b'\n']);
        let err = message(open(&header, "x.kdbx", "pw").unwrap_err());
        assert!(
            err.contains("unusually heavy") && !err.contains("MiB"),
            "{err}"
        );
    }

    #[test]
    fn kdbx_garbage_errors_without_panicking() {
        let mut seed = 0x9e37_79b9u32;
        for prefix in [
            &[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 4, 0][..],
            &[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 3, 0],
            &[0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5],
        ] {
            for len in [0usize, 3, 40, 300] {
                let mut data = prefix.to_vec();
                for _ in 0..len {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    data.push(seed as u8);
                }
                assert!(open(&data, "fuzz.kdbx", "pw").is_err());
            }
        }
    }
}

// ---- Proton Pass (PGP) ------------------------------------------------------------------------

fn proton_plain() -> String {
    json!({"version": "1.21.2", "userId": "u", "encrypted": false, "vaults": {"s": {"name": "Personal", "items": [
        {"itemId": "1", "shareId": "s", "state": 1, "aliasEmail": null, "contentFormatVersion": 1,
         "createTime": 1700000000, "modifyTime": 1700000000, "pinned": false,
         "data": {"metadata": {"name": "Forum", "note": "", "itemUuid": "x"}, "extraFields": [], "type": "login",
            "content": {"itemEmail": "", "itemUsername": "dan", "password": "pp", "urls": ["https://forum.example"],
                        "totpUri": "", "passkeys": []}}}
    ]}}})
    .to_string()
}

/// A ZIP; `password` encrypts its members with WinZip AES-256 (the zip crate doesn't write
/// ZipCrypto, which it reads the same way).
fn zip_with(files: &[(&str, &[u8])], password: Option<&str>) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let mut options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    if let Some(pw) = password {
        options = options.with_aes_encryption(zip::AesMode::Aes256, pw);
    }
    for (name, content) in files {
        w.start_file(*name, options).unwrap();
        w.write_all(content).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[cfg(feature = "import-pgp")]
mod pgp_tests {
    use ::pgp::composed::{ArmorOptions, MessageBuilder};
    use ::pgp::crypto::hash::HashAlgorithm;
    use ::pgp::crypto::sym::SymmetricKeyAlgorithm;
    use ::pgp::types::{Password, StringToKey};

    use super::*;

    /// A passphrase-encrypted message like OpenPGP.js makes for Proton Pass (SEIPD v1, AES-256,
    /// iterated and salted SHA-256 S2K).
    fn encrypt(plain: &[u8], password: &str, s2k: Option<StringToKey>, armored: bool) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let s2k =
            s2k.unwrap_or_else(|| StringToKey::new_iterated(&mut rng, HashAlgorithm::Sha256, 96));
        let mut builder = MessageBuilder::from_bytes("", plain.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_with_password(s2k, &Password::from(password))
            .unwrap();
        if armored {
            builder
                .to_armored_string(&mut rng, ArmorOptions::default())
                .unwrap()
                .into_bytes()
        } else {
            builder.to_vec(&mut rng).unwrap()
        }
    }

    #[test]
    fn proton_pass_zip_with_data_pgp() {
        let sealed = encrypt(proton_plain().as_bytes(), "proton pw", None, true);
        let data = zip_with(&[("Proton Pass/data.pgp", &sealed)], None);
        let info = import_encryption(data.clone(), "Proton Pass_export.zip".into()).unwrap();
        assert_eq!(info.format, Some(ImportFormat::ProtonPass));

        let r = open(&data, "Proton Pass_export.zip", "proton pw").unwrap();
        assert_eq!(r.format, ImportFormat::ProtonPass);
        assert_eq!(titles(&r), ["Forum"]);
        assert_eq!(r.items[0].password, "pp");
        assert_eq!(
            open(&data, "Proton Pass_export.zip", "wrong").unwrap_err(),
            PassError::InvalidPassword
        );
        assert!(message(parse_import(&data, "x.zip", None).unwrap_err()).contains("encrypted"));
    }

    #[test]
    fn pgp_file_on_its_own() {
        // Armored JSON, binary JSON, and a PGP file holding the whole ZIP.
        let zip = zip_with(
            &[("Proton Pass/data.json", proton_plain().as_bytes())],
            None,
        );
        for (sealed, name) in [
            (
                encrypt(proton_plain().as_bytes(), "pw", None, true),
                "data.pgp",
            ),
            (
                encrypt(proton_plain().as_bytes(), "pw", None, false),
                "data.pgp",
            ),
            (encrypt(&zip, "pw", None, false), "export.zip.pgp"),
        ] {
            let info = import_encryption(sealed.clone(), name.into()).unwrap();
            assert_eq!(info.format, None);
            let r = open(&sealed, name, "pw").unwrap();
            assert_eq!(titles(&r), ["Forum"], "{name}");
            assert_eq!(
                open(&sealed, name, "pw!").unwrap_err(),
                PassError::InvalidPassword
            );
        }
    }

    #[test]
    fn pgp_heavy_argon2_is_refused() {
        let mut rng = rand::thread_rng();
        // Made with 1 MiB, then patched to ask for 2^30 KiB (1 TiB).
        let s2k = StringToKey::new_argon2(&mut rng, 1, 1, 10);
        let mut sealed = encrypt(b"{}", "pw", Some(s2k), false);
        // New-format SKESK, one-octet length: version, cipher, S2K type, salt (16), t, p, m.
        assert_eq!((sealed[0], sealed[2], sealed[4]), (0xC3, 4, 4));
        assert_eq!(sealed[23], 10);
        sealed[23] = 30;
        let err = message(open(&sealed, "x.pgp", "pw").unwrap_err());
        assert!(err.contains("unusually heavy"), "{err}");
    }

    #[test]
    fn pgp_garbage_errors_without_panicking() {
        let armored = "-----BEGIN PGP MESSAGE-----\n\nwcBMA0p\n-----END PGP MESSAGE-----\n";
        assert!(open(armored.as_bytes(), "x.pgp", "pw").is_err());
        let sealed = encrypt(proton_plain().as_bytes(), "pw", None, false);
        for cut in [3, 10, 30, sealed.len() / 2, sealed.len() - 1] {
            assert!(open(&sealed[..cut], "x.pgp", "pw").is_err(), "{cut}");
        }
        let mut flipped = sealed.clone();
        let last = flipped.len() - 5;
        flipped[last] ^= 0x40;
        assert!(open(&flipped, "x.pgp", "pw").is_err());
    }
}

// ---- encrypted ZIP members ----------------------------------------------------------------------

#[test]
fn encrypted_zip_members() {
    let csv = b"name,url,username,password\nSite,https://site.example/,eve,zip-pass\n";
    {
        let data = zip_with(&[("passwords.csv", csv)], Some("zip pw"));
        let info = import_encryption(data.clone(), "export.zip".into()).unwrap();
        assert_eq!(info.format, None);
        let r = open(&data, "export.zip", "zip pw").unwrap();
        assert_eq!(r.format, ImportFormat::ChromeCsv);
        assert_eq!(r.items[0].password, "zip-pass");
        assert_eq!(
            open(&data, "export.zip", "zip PW").unwrap_err(),
            PassError::InvalidPassword
        );
        let err = message(parse_import(&data, "export.zip", None).unwrap_err());
        assert!(err.contains("encrypted"), "{err}");
    }
    let plain = zip_with(&[("passwords.csv", csv)], None);
    assert!(import_encryption(plain.clone(), "export.zip".into()).is_none());
    assert_eq!(open(&plain, "export.zip", "").unwrap().items.len(), 1);
}

#[test]
fn bitwarden_password_protected_inside_a_zip() {
    let file = testing::bitwarden(&bitwarden_plain(), "pw", pbkdf2_kdf());
    let data = zip_with(&[("bitwarden_export.json", file.as_bytes())], None);
    let r = open(&data, "bw.zip", "pw").unwrap();
    assert_eq!(r.items.len(), 2);
    assert_eq!(
        open(&data, "bw.zip", "x").unwrap_err(),
        PassError::InvalidPassword
    );
}

#[test]
fn plain_files_need_no_password() {
    let csv = "name,url,username,password\nSite,https://site.example/,eve,p\n";
    assert!(import_encryption(csv.as_bytes().to_vec(), "x.csv".into()).is_none());
    assert!(import_encryption(bitwarden_plain().into_bytes(), "x.json".into()).is_none());
    assert!(import_encryption(Vec::new(), "".into()).is_none());
    assert_eq!(
        open(csv.as_bytes(), "x.csv", "anything")
            .unwrap()
            .items
            .len(),
        1
    );
}

#[test]
fn bounds() {
    use encrypted::*;
    let k = Kind::Bitwarden;
    assert!(check_pbkdf2(k, 600_000).is_ok());
    assert!(check_pbkdf2(k, u64::from(MAX_PBKDF2_ITERATIONS) + 1).is_err());
    assert!(check_pbkdf2(k, 0).is_err());
    assert!(check_argon2(k, 64 * 1024, 3, 4).is_ok());
    assert!(check_argon2(k, 1024 * 1024, 10, 4).is_ok());
    assert!(check_argon2(k, 1024 * 1024 + 1, 1, 1).is_err());
    assert!(check_argon2(k, 1024 * 1024, 17, 1).is_err());
    assert!(check_argon2(k, 64 * 1024, 1, 65).is_err());
    assert!(check_scrypt(k, 1 << 15, 8, 1).is_ok());
    assert!(check_scrypt(k, 1 << 21, 8, 1).is_err());
    assert!(check_scrypt(k, 1000, 8, 1).is_err());
    assert!(check_aes_kdf(k, 60_000_000).is_ok());
    assert!(check_aes_kdf(k, MAX_AES_KDF_ROUNDS + 1).is_err());
}
