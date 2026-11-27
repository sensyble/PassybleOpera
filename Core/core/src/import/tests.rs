//! Import tests. Fixtures are hand-written from each format's documented structure; all secrets are dummies.

use std::io::{Cursor, Write};

use base64::Engine;
use serde_json::json;

use super::*;
use crate::model::{CardData, IdentityData, PasswordHistoryEntry, MAX_PASSWORD_HISTORY};
use crate::vault::KdfParams;

const SECRET: &str = "JBSWY3DPEHPK3PXP";
/// RFC 6238's SHA-1 test key, base32 of "12345678901234567890".
const RFC_SECRET: &[u8] = b"12345678901234567890";

fn parse(data: &str, name: &str) -> ImportReport {
    parse_import(data.as_bytes(), name, None).expect("parses")
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

fn vault() -> Arc<Vault> {
    Vault::create_with_kdf(
        "pw",
        "dev",
        KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
            ..Default::default()
        },
    )
    .unwrap()
}

fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in files {
        w.start_file(*name, options).unwrap();
        w.write_all(content.as_bytes()).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn pb_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn pb_bytes(out: &mut Vec<u8>, tag: u64, bytes: &[u8]) {
    pb_varint(out, tag << 3 | 2);
    pb_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn pb_uint(out: &mut Vec<u8>, tag: u64, v: u64) {
    pb_varint(out, tag << 3);
    pb_varint(out, v);
}

fn otp_param(
    secret: &[u8],
    name: &str,
    issuer: &str,
    algo: u64,
    digits: u64,
    kind: u64,
) -> Vec<u8> {
    let mut p = Vec::new();
    pb_bytes(&mut p, 1, secret);
    pb_bytes(&mut p, 2, name.as_bytes());
    pb_bytes(&mut p, 3, issuer.as_bytes());
    pb_uint(&mut p, 4, algo);
    pb_uint(&mut p, 5, digits);
    pb_uint(&mut p, 6, kind);
    if kind == 1 {
        pb_uint(&mut p, 7, 3);
    }
    p
}

fn migration_uri(params: &[Vec<u8>], size: u64, index: u64, id: u64) -> String {
    let mut payload = Vec::new();
    for p in params {
        pb_bytes(&mut payload, 1, p);
    }
    pb_uint(&mut payload, 2, 1);
    pb_uint(&mut payload, 3, size);
    pb_uint(&mut payload, 4, index);
    pb_uint(&mut payload, 5, id);
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let data: String = url::form_urlencoded::byte_serialize(b64.as_bytes()).collect();
    format!("otpauth-migration://offline?data={data}")
}

#[test]
fn google_authenticator_migration() {
    let uri = migration_uri(
        &[
            otp_param(RFC_SECRET, "GitHub:alice", "GitHub", 1, 1, 2),
            otp_param(RFC_SECRET, "bob@example.com", "", 2, 2, 2),
            otp_param(RFC_SECRET, "counter", "Bank", 1, 1, 1),
        ],
        1,
        0,
        7,
    );
    let r = parse(&format!("Exported:\n{uri}\n"), "");
    assert_eq!(r.format, ImportFormat::GoogleAuthenticator);
    assert_eq!(titles(&r), ["GitHub", "bob@example.com"]);
    let gh = find(&r, "GitHub");
    assert_eq!(gh.username, "alice");
    assert!(gh.password.is_empty() && gh.urls.is_empty());
    // RFC 6238: SHA-1 at T=59 gives 94287082, six digits 287082.
    assert_eq!(
        crate::totp_generate(gh.totp.clone().unwrap(), 59)
            .unwrap()
            .code,
        "287082"
    );
    let bob = find(&r, "bob@example.com");
    let cfg = crate::totp_parse(bob.totp.clone().unwrap()).unwrap();
    assert_eq!(cfg.algorithm, crate::TotpAlgorithm::Sha256);
    assert_eq!(cfg.digits, 8);
    assert_eq!(cfg.account.as_deref(), Some("bob@example.com"));
    assert_eq!(r.skipped.len(), 1);
    assert!(r.skipped[0].reason.contains("HOTP"));
}

#[test]
fn google_authenticator_batches_warn_when_incomplete() {
    let first = migration_uri(&[otp_param(RFC_SECRET, "a", "A", 1, 1, 2)], 3, 0, 42);
    let second = migration_uri(&[otp_param(RFC_SECRET, "b", "B", 1, 1, 2)], 3, 1, 42);
    let r = parse(&format!("{first}\n{second}"), "");
    assert_eq!(r.items.len(), 2);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("3 QR codes") && w.contains("only 2")));
}

fn migration_link(payload: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let data: String = url::form_urlencoded::byte_serialize(b64.as_bytes()).collect();
    format!("otpauth-migration://offline?data={data}")
}

#[test]
fn google_authenticator_damaged_link_is_skipped_not_panicking() {
    // Field 1 claims 16 bytes but has 2; a 10-byte varint length; an unknown wire type.
    for payload in [
        &[0x0a, 0x10, 0x0a, 0x02][..],
        &[
            0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ],
        &[0x0b, 0x00],
    ] {
        let r = parse(&migration_link(payload), "");
        assert!(r.items.is_empty());
        assert_eq!(r.skipped.len(), 1, "{payload:?}");
    }
    let r = parse("otpauth-migration://offline?data=%%%", "");
    assert_eq!(r.skipped.len(), 1);
}

#[cfg(feature = "import-qr")]
#[test]
fn google_authenticator_qr_image() {
    let uri = migration_uri(
        &[otp_param(RFC_SECRET, "alice", "GitHub", 1, 1, 2)],
        1,
        0,
        9,
    );
    let code = qrcode::QrCode::new(uri.as_bytes()).unwrap();
    let width = code.width();
    let colors = code.to_colors();
    let (scale, quiet) = (6u32, 4u32);
    let side = (width as u32 + 2 * quiet) * scale;
    let img = image::GrayImage::from_fn(side, side, |x, y| {
        let (mx, my) = (x / scale, y / scale);
        let dark = mx >= quiet
            && my >= quiet
            && mx < quiet + width as u32
            && my < quiet + width as u32
            && colors[((my - quiet) as usize) * width + (mx - quiet) as usize]
                == qrcode::Color::Dark;
        image::Luma([if dark { 0 } else { 255 }])
    });
    let mut png = Vec::new();
    img.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    let r = parse_import(&png, "Screenshot.png", None).unwrap();
    assert_eq!(r.format, ImportFormat::GoogleAuthenticator);
    assert_eq!(titles(&r), ["GitHub"]);
    assert_eq!(r.items[0].username, "alice");

    let mut blank = Vec::new();
    image::GrayImage::from_pixel(64, 64, image::Luma([255]))
        .write_to(&mut Cursor::new(&mut blank), image::ImageFormat::Png)
        .unwrap();
    assert!(parse_import(&blank, "blank.png", None).is_err());
}

/// A Passyble Server pairing QR code on the clipboard (RGBA, dark-on-light and with transparency)
/// and in a PNG.
#[cfg(feature = "import-qr")]
#[test]
fn pairing_qr_from_rgba_and_png() {
    let link = "pass+server://203.0.113.7:8443/dav/alice/personal.vault?v=1&user=alice&token=pst_kr3RuvCRcaQ29nq0oGvtM8RWx1_YAaPvx1qy-J047Hw&name=Laptop&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g";
    let code = qrcode::QrCode::with_error_correction_level(link, qrcode::EcLevel::L).unwrap();
    let width = code.width();
    let colors = code.to_colors();
    let (scale, quiet) = (4u32, 4u32);
    let side = (width as u32 + 2 * quiet) * scale;
    let dark = |x: u32, y: u32| {
        let (mx, my) = (x / scale, y / scale);
        mx >= quiet
            && my >= quiet
            && mx < quiet + width as u32
            && my < quiet + width as u32
            && colors[((my - quiet) as usize) * width + (mx - quiet) as usize]
                == qrcode::Color::Dark
    };
    let mut rgba = Vec::new();
    for y in 0..side {
        for x in 0..side {
            // Light modules are transparent, as in some snipping tools.
            rgba.extend_from_slice(if dark(x, y) {
                &[20, 20, 30, 255]
            } else {
                &[0, 0, 0, 0]
            });
        }
    }
    assert_eq!(crate::qr_decode_rgba(side, side, &rgba).unwrap(), [link]);
    assert!(crate::qr_decode_rgba(side, side, &rgba[4..]).is_err());
    assert!(crate::qr_decode_rgba(0, 0, &[]).is_err());

    let img = image::GrayImage::from_fn(side, side, |x, y| {
        image::Luma([if dark(x, y) { 0 } else { 255 }])
    });
    let mut png = Vec::new();
    img.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    assert_eq!(crate::qr_decode_image(&png).unwrap(), [link]);
}

#[cfg(not(feature = "import-qr"))]
#[test]
fn qr_images_need_the_feature() {
    let err = parse_import(b"\x89PNG\r\n\x1a\n0000", "qr.png", None).unwrap_err();
    let err = err.to_string();
    assert!(
        err.contains("camera") && !err.contains("this build"),
        "{err}"
    );
}

#[test]
fn otpauth_uri_list() {
    let text = format!(
        "otpauth://totp/Example:alice@example.com?secret={SECRET}&issuer=Example\n\
         \n\
         otpauth://totp/plain-account?secret={SECRET}\n\
         otpauth://hotp/Counter:x?secret={SECRET}&counter=1\n\
         otpauth://totp/Bad?secret=not*base32\n"
    );
    let r = parse(&text, "codes.txt");
    assert_eq!(r.format, ImportFormat::OtpauthUris);
    assert_eq!(titles(&r), ["Example", "plain-account"]);
    assert_eq!(find(&r, "Example").username, "alice@example.com");
    assert_eq!(r.skipped.len(), 2);
}

#[test]
fn aegis_plain() {
    let v = json!({"version": 1, "header": {"slots": null, "params": null}, "db": {"version": 2, "entries": [
        {"type": "totp", "uuid": "0e5b1c8a-0000-4000-8000-000000000001", "name": "ivan@example.com", "issuer": "GitHub",
         "note": "work account", "favorite": true, "icon": null,
         "info": {"secret": SECRET, "algo": "SHA256", "digits": 8, "period": 60}},
        {"type": "hotp", "uuid": "2", "name": "bank", "issuer": "Bank", "info": {"secret": SECRET, "algo": "SHA1", "digits": 6, "counter": 0}},
        {"type": "steam", "uuid": "3", "name": "me", "issuer": "Steam", "info": {"secret": SECRET, "algo": "SHA1", "digits": 5, "period": 30}}
    ], "groups": []}});
    let r = parse(&v.to_string(), "aegis-export-plain.json");
    assert_eq!(r.format, ImportFormat::Aegis);
    assert_eq!(titles(&r), ["GitHub"]);
    let item = &r.items[0];
    assert_eq!(item.username, "ivan@example.com");
    assert_eq!(item.notes, "work account");
    assert!(item.favorite);
    let cfg = crate::totp_parse(item.totp.clone().unwrap()).unwrap();
    assert_eq!((cfg.digits, cfg.period), (8, 60));
    assert_eq!(cfg.algorithm, crate::TotpAlgorithm::Sha256);
    assert_eq!(r.skipped.len(), 2);
}

#[test]
fn aegis_encrypted_is_rejected() {
    let v = json!({"version": 1, "header": {"slots": [{"type": 1, "uuid": "x", "key": "00", "key_params": {"nonce": "00", "tag": "00"}}],
        "params": {"nonce": "00", "tag": "00"}}, "db": "c2VjcmV0"});
    let err = parse_import(v.to_string().as_bytes(), "aegis.json", None).unwrap_err();
    assert!(err.to_string().contains("encrypted"), "{err}");
}

#[test]
fn twofas_plain_and_encrypted() {
    let v = json!({"services": [
        {"name": "Google", "secret": SECRET, "updatedAt": 1700000000000u64,
         "otp": {"label": "jane@gmail.com", "account": "jane@gmail.com", "issuer": "Google", "digits": 6, "period": 30,
                 "algorithm": "SHA1", "tokenType": "TOTP", "source": "Link"},
         "order": {"position": 0}, "icon": {"selected": "Label"}},
        {"name": "Steam", "secret": SECRET, "otp": {"account": "me", "tokenType": "STEAM", "digits": 5}}
    ], "groups": [], "updatedAt": 1700000000000u64, "schemaVersion": 4, "appVersionCode": 5000000, "appOrigin": "android"});
    let r = parse(&v.to_string(), "backup.2fas");
    assert_eq!(r.format, ImportFormat::TwoFas);
    assert_eq!(titles(&r), ["Google"]);
    assert_eq!(r.items[0].username, "jane@gmail.com");
    assert_eq!(r.skipped.len(), 1);

    let enc = json!({"services": [], "groups": [], "schemaVersion": 4, "appOrigin": "ios",
        "servicesEncrypted": "AAAA:BBBB:CCCC", "reference": "DDDD"});
    let err = parse_import(enc.to_string().as_bytes(), "backup.2fas", None).unwrap_err();
    assert!(err.to_string().contains("encrypted"));
}

#[test]
fn chrome_csv() {
    let csv = "name,url,username,password,note\n\
               github.com,https://github.com/login,alice,gh-pass-1,\n\
               Example,https://www.example.com/,bob@example.com,\"ex,pass\"\"q\",\"Recovery codes\nin the drawer\"\n\
               ,,,,\n";
    let r = parse(csv, "Chrome Passwords.csv");
    assert_eq!(r.format, ImportFormat::ChromeCsv);
    assert_eq!(titles(&r), ["github.com", "Example"]);
    let ex = find(&r, "Example");
    assert_eq!(ex.password, "ex,pass\"q");
    assert_eq!(ex.notes, "Recovery codes\nin the drawer");
    assert_eq!(ex.urls, ["https://www.example.com/"]);
}

#[test]
fn chrome_csv_with_bom_and_crlf() {
    let csv = "\u{feff}name,url,username,password\r\nsite,https://site.test/,u,p\r\n";
    let r = parse(csv, "x.csv");
    assert_eq!(r.format, ImportFormat::ChromeCsv);
    assert_eq!(r.items[0].password, "p");
}

#[test]
fn firefox_csv() {
    let csv = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
               \"https://accounts.example.org\",\"carol\",\"fx-pass\",,\"https://accounts.example.org\",\"{5ec0a0d4-0000-4000-8000-000000000001}\",\"1700000000000\",\"1700000000000\",\"1700000000000\"\n\
               \"chrome://FirefoxAccounts\",\"uid\",\"{}\",\"Firefox Accounts credentials\",,\"{x}\",\"1\",\"1\",\"1\"\n";
    let r = parse(csv, "logins.csv");
    assert_eq!(r.format, ImportFormat::FirefoxCsv);
    assert_eq!(titles(&r), ["example.org"]);
    assert_eq!(r.items[0].username, "carol");
    assert_eq!(r.skipped.len(), 1);
}

#[test]
fn apple_csv() {
    let csv = format!(
        "Title,URL,Username,Password,Notes,OTPAuth\n\
         GitLab (alice),https://gitlab.com/,alice,gl-pass,,otpauth://totp/GitLab:alice?secret={SECRET}&issuer=GitLab\n\
         Wi-Fi,,,,router in the hall,\n"
    );
    let r = parse(&csv, "Passwords.csv");
    assert_eq!(r.format, ImportFormat::AppleCsv);
    let gl = find(&r, "GitLab (alice)");
    assert!(gl.has_totp());
    assert_eq!(find(&r, "Wi-Fi").notes, "router in the hall");
}

#[test]
fn proton_pass_csv() {
    let csv = format!(
        "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
         login,Proton,\"https://account.proton.me, https://mail.proton.me\",dave@proton.me,,pr-pass,,otpauth://totp/Proton:dave?secret={SECRET},1700000000,1700000000,Personal\n\
         note,Wifi,,,,,The wifi password is hunter2,,1700000000,1700000000,Personal\n\
         creditCard,Visa,,,,,,,1700000000,1700000000,Personal\n"
    );
    let r = parse(&csv, "Proton Pass_export.csv");
    assert_eq!(r.format, ImportFormat::ProtonPassCsv);
    let login = find(&r, "Proton");
    assert_eq!(login.username, "dave@proton.me");
    assert_eq!(
        login.urls,
        ["https://account.proton.me", "https://mail.proton.me"]
    );
    assert!(login.has_totp());
    assert_eq!(find(&r, "Wifi").kind, ItemKind::Note);
    assert_eq!(r.skipped.len(), 1);
}

#[test]
fn onepassword_csv() {
    let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
               Dropbox,https://www.dropbox.com/,erin,db-pass,,true,false,,shared folder\n\
               Old,https://old.example.com,erin,old,,false,true,,\n";
    let r = parse(csv, "1PasswordExport.csv");
    assert_eq!(r.format, ImportFormat::OnePasswordCsv);
    assert_eq!(titles(&r), ["Dropbox"]);
    assert!(r.items[0].favorite);
    assert_eq!(r.skipped.len(), 1);
}

#[test]
fn bitwarden_csv() {
    let csv = format!(
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
         Social,1,login,Twitter,,\"Security question: pet\",0,\"https://twitter.com,https://x.com\",frank,tw-pass,{SECRET}\n\
         ,,note,Server notes,ssh root@10.0.0.1,,0,,,,\n\
         ,,card,Visa,,,0,,,,\n"
    );
    let r = parse(&csv, "bitwarden_export.csv");
    assert_eq!(r.format, ImportFormat::BitwardenCsv);
    let tw = find(&r, "Twitter");
    assert!(tw.favorite);
    assert_eq!(tw.urls, ["https://twitter.com", "https://x.com"]);
    assert_eq!(tw.totp.as_deref(), Some(SECRET));
    assert_eq!(tw.notes, "");
    assert_eq!(
        tw.fields,
        [CustomField {
            name: "Security question".into(),
            value: "pet".into(),
            kind: FieldKind::Text
        }]
    );
    assert_eq!(tw.tags, ["Social"]);
    assert_eq!(find(&r, "Server notes").kind, ItemKind::Note);
    // Bitwarden's CSV has no card columns: such a row is skipped.
    assert_eq!(r.skipped.len(), 1);
}

#[test]
fn keepassxc_csv() {
    let csv = format!(
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
         \"Root\",\"Router\",\"admin\",\"rt-pass\",\"http://192.168.1.1\",\"\",\"otpauth://totp/Router:admin?secret={SECRET}&period=30&digits=6&issuer=Router\",\"0\",\"2024-01-01T00:00:00Z\",\"2024-01-01T00:00:00Z\"\n\
         \"Root/Recycle Bin\",\"Deleted\",\"x\",\"y\",\"\",\"\",\"\",\"0\",\"\",\"\"\n"
    );
    let r = parse(&csv, "keepass.csv");
    assert_eq!(r.format, ImportFormat::KeepassxcCsv);
    assert_eq!(titles(&r), ["Router"]);
    assert!(r.items[0].has_totp());
    assert!(r.items[0].tags.is_empty(), "the root group is no tag");
    assert_eq!(r.skipped.len(), 1);
    let nested = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\n\"Root/Work/Clients\",\"CRM\",\"a\",\"b\",\"\",\"\"\n";
    assert_eq!(parse(nested, "k.csv").items[0].tags, ["Work/Clients"]);
}

#[test]
fn lastpass_csv() {
    let csv = "url,username,password,totp,extra,name,grouping,fav\n\
               https://www.reddit.com/login,gina,rd-pass,,,Reddit,Social,0\n\
               http://sn,,,,\"NoteType:Server\nHostname:db1\",DB server,,1\n";
    let r = parse(csv, "lastpass_export.csv");
    assert_eq!(r.format, ImportFormat::LastpassCsv);
    assert_eq!(find(&r, "Reddit").username, "gina");
    assert_eq!(find(&r, "Reddit").tags, ["Social"]);
    let note = find(&r, "DB server");
    assert_eq!(note.kind, ItemKind::Note);
    assert!(note.urls.is_empty());
    assert!(note.favorite);
}

#[test]
fn dashlane_csv_and_zip() {
    let csv = "username,username2,username3,title,password,note,url,category,otpUrl\n\
               henry,henry.alt,,Spotify,sp-pass,,https://spotify.com,Entertainment,\n";
    let r = parse(csv, "credentials.csv");
    assert_eq!(r.format, ImportFormat::DashlaneCsv);
    assert_eq!(r.items[0].notes, "");
    assert_eq!(r.items[0].fields[0].name, "Alternative username");
    assert_eq!(r.items[0].fields[0].value, "henry.alt");
    assert_eq!(r.items[0].tags, ["Entertainment"]);

    let notes = "title,note\nAlarm code,1234\n";
    let data = zip(&[
        ("credentials.csv", csv),
        ("securenotes.csv", notes),
        ("ids.csv", "type,number\npassport,1\n"),
    ]);
    let r = parse_import(&data, "Dashlane Export.zip", None).unwrap();
    assert_eq!(r.format, ImportFormat::DashlaneCsv);
    assert_eq!(titles(&r), ["Spotify", "Alarm code"]);
    assert_eq!(find(&r, "Alarm code").kind, ItemKind::Note);
    assert!(r.warnings.iter().any(|w| w.contains("ids.csv")));
}

#[test]
fn unknown_csv_is_rejected() {
    assert!(parse_import(b"a,b,c\n1,2,3\n", "x.csv", None).is_err());
}

fn passkey_key() -> (Vec<u8>, String) {
    use p256::pkcs8::EncodePrivateKey;
    let key = crate::passkey::new_signing_key();
    let der = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let b64 = crate::b64url_encode(der.clone());
    (der, b64)
}

fn bitwarden_export(key_b64: &str) -> serde_json::Value {
    json!({"encrypted": false, "folders": [], "items": [
        {"id": "7d1d9a62-0000-4000-8000-000000000001", "organizationId": null, "folderId": null, "type": 1, "reprompt": 0,
         "name": "WebAuthn.io", "notes": null, "favorite": false,
         "fields": [{"name": "PIN", "value": "1234", "type": 1, "linkedId": null},
                    {"name": "linked", "value": null, "type": 3, "linkedId": 100}],
         "login": {
            "fido2Credentials": [{
                "credentialId": "4f6b3c2a-1d2e-4f50-8a9b-0c1d2e3f4a5b", "keyType": "public-key", "keyAlgorithm": "ECDSA",
                "keyCurve": "P-256", "keyValue": key_b64, "rpId": "webauthn.io", "userHandle": "AQIDBA",
                "userName": "kim", "counter": "3", "rpName": "WebAuthn.io", "userDisplayName": "Kim",
                "discoverable": "true", "creationDate": "2024-03-01T10:00:00.000Z"}],
            "uris": [{"match": null, "uri": "https://webauthn.io/"}],
            "username": "kim", "password": "wa-pass",
            "totp": format!("otpauth://totp/WebAuthn:kim?secret={SECRET}")},
         "collectionIds": null, "creationDate": "2024-03-01T10:00:00.000Z", "deletedDate": null},
        {"type": 2, "name": "Secure note", "notes": "secret note", "secureNote": {"type": 0}, "favorite": true},
        {"type": 3, "name": "Visa", "card": {"number": "4111111111111111"}},
        {"type": 1, "name": "Trashed", "login": {"username": "x", "password": "y"}, "deletedDate": "2024-04-01T00:00:00Z"},
        {"type": 1, "name": "Bad passkey", "login": {"username": "z", "password": "p", "uris": [{"uri": "https://bad.example"}],
            "fido2Credentials": [{"credentialId": "b64.AAEC", "keyAlgorithm": "ECDSA", "keyCurve": "P-256",
                "keyValue": "bm90LWEta2V5", "rpId": "bad.example", "userHandle": "AQID", "userName": "z"}]}}
    ]})
}

#[test]
fn bitwarden_json_with_passkey() {
    let (der, key_b64) = passkey_key();
    let r = parse(
        &bitwarden_export(&key_b64).to_string(),
        "bitwarden_export.json",
    );
    assert_eq!(r.format, ImportFormat::BitwardenJson);
    assert_eq!(
        titles(&r),
        ["WebAuthn.io", "Secure note", "Visa", "Bad passkey"]
    );
    let item = find(&r, "WebAuthn.io");
    assert_eq!(item.notes, "");
    assert_eq!(
        item.fields,
        [CustomField {
            name: "PIN".into(),
            value: "1234".into(),
            kind: FieldKind::Hidden
        }]
    );
    let card = find(&r, "Visa");
    assert_eq!(card.kind, ItemKind::Card);
    assert_eq!(card.card.as_ref().unwrap().number, "4111111111111111");
    assert!(item.has_totp());
    assert_eq!(item.created_at, 1_709_287_200_000);
    let pk = &item.passkeys[0];
    assert_eq!(pk.rp_id, "webauthn.io");
    assert_eq!(pk.user_handle, [1, 2, 3, 4]);
    assert_eq!(
        pk.credential_id,
        [
            0x4f, 0x6b, 0x3c, 0x2a, 0x1d, 0x2e, 0x4f, 0x50, 0x8a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f,
            0x4a, 0x5b
        ]
    );
    assert_eq!(pk.private_key_pkcs8, der);
    assert_eq!(pk.sign_count, 3);
    assert_eq!(pk.user_name, "kim");
    assert_eq!(pk.rp_name.as_deref(), Some("WebAuthn.io"));
    crate::passkey_assert(pk.clone(), vec![7; 32], true).unwrap();
    assert!(find(&r, "Bad passkey").passkeys.is_empty());
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("Bad passkey") && w.contains("bad.example")));
    assert_eq!(find(&r, "Secure note").kind, ItemKind::Note);
    assert_eq!(r.skipped.len(), 1, "the trashed login");
}

#[test]
fn bitwarden_encrypted_is_rejected() {
    let v = json!({"encrypted": true, "passwordProtected": true, "salt": "c2FsdA==", "kdfType": 0, "kdfIterations": 600000,
        "encKeyValidation_DO_NOT_EDIT": "2.AAAA|BBBB|CCCC", "data": "2.DDDD|EEEE|FFFF"});
    let err = parse_import(
        v.to_string().as_bytes(),
        "bitwarden_encrypted_export.json",
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("encrypted"));
    let v = json!({"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "2.x", "folders": [], "items": [{"type": 1, "name": "2.enc"}]});
    assert!(parse_import(v.to_string().as_bytes(), "", None).is_err());
}

fn proton_data() -> String {
    json!({"version": "1.21.2", "userId": "user", "encrypted": false, "vaults": {"share1": {"name": "Personal", "description": "",
        "display": {"color": 0, "icon": 0}, "items": [
        {"itemId": "i1", "shareId": "share1", "state": 1, "aliasEmail": null, "contentFormatVersion": 6,
         "createTime": 1700000000, "modifyTime": 1700000000, "pinned": true,
         "data": {"metadata": {"name": "Proton Login", "note": "main account", "itemUuid": "x"},
            "extraFields": [{"fieldName": "Backup code", "type": "hidden", "data": {"content": "1111-2222"}}],
            "type": "login",
            "content": {"itemEmail": "leo@proton.me", "itemUsername": "", "password": "pp",
                "urls": ["https://account.proton.me/"],
                "totpUri": format!("otpauth://totp/Proton:leo%40proton.me?secret={SECRET}&issuer=Proton"),
                "passkeys": [{"keyId": "k", "content": "AAAA", "domain": "proton.me", "rpId": "proton.me", "rpName": "Proton",
                    "userName": "leo", "userDisplayName": "Leo", "userId": "AQID", "createTime": 1700000000, "note": "",
                    "credentialId": "AQID", "userHandle": "AQID"}]}}},
        {"itemId": "i2", "state": 1, "createTime": 1700000000,
         "data": {"metadata": {"name": "Shopping list", "note": "milk"}, "extraFields": [], "type": "note", "content": {}}},
        {"itemId": "i3", "state": 2, "data": {"metadata": {"name": "Old", "note": ""}, "type": "login",
            "content": {"itemUsername": "o", "password": "o"}}},
        {"itemId": "i4", "state": 1, "data": {"metadata": {"name": "Alias", "note": ""}, "type": "alias", "content": {}}}
    ]}}})
    .to_string()
}

#[test]
fn proton_pass_zip() {
    let data = zip(&[("Proton Pass/data.json", &proton_data())]);
    let r = parse_import(&data, "Proton Pass_export_2024.zip", None).unwrap();
    assert_eq!(r.format, ImportFormat::ProtonPass);
    assert_eq!(titles(&r), ["Proton Login", "Shopping list"]);
    let login = find(&r, "Proton Login");
    assert_eq!(login.username, "leo@proton.me");
    assert_eq!(login.notes, "main account");
    assert_eq!(
        login.fields,
        [CustomField {
            name: "Backup code".into(),
            value: "1111-2222".into(),
            kind: FieldKind::Hidden
        }]
    );
    assert!(login.tags.is_empty(), "one vault: no tag");
    assert!(login.favorite && login.has_totp());
    assert!(login.passkeys.is_empty());
    assert_eq!(login.created_at, 1_700_000_000_000);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("passkey") && w.contains("proton.me")));
    assert_eq!(r.skipped.len(), 2);
    assert_eq!(parse(&proton_data(), "data.json").items.len(), 2);
}

#[test]
fn proton_pass_encrypted_is_rejected() {
    let pgp = "-----BEGIN PGP MESSAGE-----\n\nwcBMA0p\n-----END PGP MESSAGE-----\n";
    assert!(parse_import(pgp.as_bytes(), "Proton Pass_export.pgp", None)
        .unwrap_err()
        .to_string()
        .contains("encrypted"));
    let data = zip(&[("Proton Pass/data.pgp", pgp)]);
    assert!(parse_import(&data, "export.zip", None)
        .unwrap_err()
        .to_string()
        .contains("encrypted"));
}

fn onepux_data() -> String {
    json!({"accounts": [{"attrs": {"accountName": "Me", "name": "Me", "avatar": "", "email": "me@example.com", "uuid": "A",
        "domain": "https://my.1password.com/"}, "vaults": [{"attrs": {"uuid": "V", "desc": "", "avatar": "", "name": "Personal", "type": "P"},
        "items": [
        {"uuid": "1", "favIndex": 1, "createdAt": 1614298956, "updatedAt": 1635346445, "state": "active", "categoryUuid": "001",
         "details": {"loginFields": [
                {"value": "mia", "id": "", "name": "username", "fieldType": "T", "designation": "username"},
                {"value": "op-pass", "id": "", "name": "password", "fieldType": "P", "designation": "password"}],
            "notesPlain": "family plan",
            "sections": [{"title": "", "name": "", "fields": [
                {"title": "one-time password", "id": "TOTP_1", "value": {"totp": format!("otpauth://totp/Netflix:mia?secret={SECRET}&issuer=Netflix")},
                 "guarded": false, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default"}},
                {"title": "PIN", "id": "pin", "value": {"concealed": "0000"}},
                {"title": "Passkey", "id": "pk", "value": {"passkey": {"credentialId": "abc", "rpId": "netflix.com", "userHandle": "xyz"}}}]}],
            "passwordHistory": []},
         "overview": {"subtitle": "mia", "urls": [{"label": "", "url": "https://www.netflix.com/login"}], "title": "Netflix",
            "url": "https://www.netflix.com/login", "ps": 100, "pbe": 0, "pgrng": false}},
        {"uuid": "2", "favIndex": 0, "createdAt": 1614298956, "updatedAt": 1614298956, "state": "active", "categoryUuid": "003",
         "details": {"loginFields": [], "notesPlain": "door code 4321", "sections": [], "passwordHistory": []},
         "overview": {"title": "Door", "ps": 0}},
        {"uuid": "3", "state": "active", "categoryUuid": "005", "details": {"password": "db-root"},
         "overview": {"title": "DB root", "url": "https://db.internal.example"}},
        {"uuid": "4", "state": "active", "categoryUuid": "002", "details": {}, "overview": {"title": "Amex"}},
        {"uuid": "5", "state": "archived", "categoryUuid": "001", "details": {}, "overview": {"title": "Old"}}
    ]}]}]})
    .to_string()
}

#[test]
fn onepassword_1pux() {
    let data = zip(&[
        ("export.attributes", "{\"version\":3,\"description\":\"1Password Unencrypted Export\",\"createdAt\":1635346445}"),
        ("export.data", &onepux_data()),
    ]);
    let r = parse_import(&data, "1PasswordExport-ABC.1pux", None).unwrap();
    assert_eq!(r.format, ImportFormat::OnePassword);
    assert_eq!(titles(&r), ["Netflix", "Door", "DB root", "Amex"]);
    assert_eq!(find(&r, "Amex").kind, ItemKind::Card);
    let nf = find(&r, "Netflix");
    assert_eq!(
        (nf.username.as_str(), nf.password.as_str()),
        ("mia", "op-pass")
    );
    assert_eq!(nf.urls, ["https://www.netflix.com/login"]);
    assert!(nf.has_totp() && nf.favorite);
    assert_eq!(nf.notes, "family plan");
    assert_eq!(nf.fields[0].name, "PIN");
    assert_eq!(nf.fields[0].kind, FieldKind::Hidden);
    assert_eq!(find(&r, "Door").kind, ItemKind::Note);
    assert_eq!(find(&r, "DB root").password, "db-root");
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("Netflix") && w.contains("passkey")));
    assert_eq!(r.skipped.len(), 1, "the archived item");
}

#[test]
fn explicit_format_is_respected() {
    let csv = "name,url,username,password\nsite,https://site.test,u,p\n";
    let r = parse_import(csv.as_bytes(), "", Some(ImportFormat::GenericCsv)).unwrap();
    assert_eq!(r.format, ImportFormat::GenericCsv);
    assert!(parse_import(csv.as_bytes(), "", Some(ImportFormat::Aegis)).is_err());
}

#[test]
fn hostile_input_errors_without_panicking() {
    assert!(parse_import(b"", "x", None).is_err());
    assert!(parse_import(&vec![b'a'; MAX_IMPORT_BYTES + 1], "x", None).is_err());
    assert!(
        parse_import(b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5", "db.kdbx", None)
            .unwrap_err()
            .to_string()
            .contains("KeePass")
    );
    assert!(parse_import(b"PK\x03\x04garbage", "x.zip", None).is_err());
    assert!(parse_import(b"{\"items\": 5}", "x.json", None).is_err());
    assert!(parse_import(&[0xff, 0xfe, 0x00], "x", None).is_err());
    let deep = "[".repeat(10_000);
    assert!(parse_import(deep.as_bytes(), "x.json", None).is_err());
    // Pseudo-random bytes behind each magic prefix.
    let mut seed = 0x1234_5678u32;
    for prefix in [
        &b"PK\x03\x04"[..],
        b"{",
        b"otpauth-migration://offline?data=",
        b"\x89PNG\r\n\x1a\n",
        b"name,url,username,password\n",
    ] {
        for len in [0usize, 1, 7, 64, 512] {
            let mut data = prefix.to_vec();
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                data.push(seed as u8);
            }
            let _ = parse_import(&data, "fuzz", None);
        }
    }
}

#[test]
fn zip_members_are_read_with_a_cap() {
    // A member that inflates beyond the limit is refused, whatever its header claims.
    let big = " ".repeat(64 * 1024);
    let data = zip(&[("export.data", &big)]);
    assert!(data.len() < 4096);
    let mut archive = zip::ZipArchive::new(Cursor::new(&data[..])).unwrap();
    let err = archive::read_member(&mut archive, 0, 1024, None).unwrap_err();
    assert!(err.to_string().contains("too large"), "{err}");
    assert_eq!(
        archive::read_member(&mut archive, 0, big.len(), None)
            .unwrap()
            .len(),
        big.len()
    );
}

fn login(title: &str, url: &str, username: &str, password: &str) -> Item {
    Item {
        kind: ItemKind::Login,
        title: title.into(),
        urls: vec![url.into()],
        username: username.into(),
        password: password.into(),
        ..Default::default()
    }
}

fn batch(data: &str) -> ImportBatch {
    ImportBatch::new(parse(data, ""))
}

#[test]
fn authenticator_entry_merges_into_matching_login() {
    let v = vault();
    let gh = v
        .upsert(login("GitHub", "https://github.com/login", "alice", "pw"))
        .unwrap();
    v.upsert(login(
        "GitHub work",
        "https://github.com",
        "alice-work",
        "pw2",
    ))
    .unwrap();
    let text = format!(
        "otpauth://totp/GitHub:alice?secret={SECRET}&issuer=GitHub\n\
         otpauth://totp/Slack:alice?secret={SECRET}&issuer=Slack\n"
    );
    let b = batch(&text);
    let p = b.preview(v.clone());
    assert_eq!(
        (p.to_add, p.to_merge, p.duplicates, p.conflicts),
        (1, 1, 0, 0)
    );
    assert_eq!(p.entries[0].action, ImportAction::Merge);
    assert_eq!(p.entries[0].target_id.as_deref(), Some(gh.id.as_str()));
    assert_eq!(p.entries[0].adds, ["2FA"]);
    assert!(!v.get(gh.id.clone()).unwrap().has_totp());

    let result = b.commit(v.clone()).unwrap();
    assert_eq!(
        result,
        ImportResult {
            added: 1,
            merged: 1,
            conflicts: 0,
            skipped: 0
        }
    );
    assert!(v.get(gh.id.clone()).unwrap().has_totp());
    assert_eq!(v.items().len(), 3);

    let again = batch(&text).commit(v.clone()).unwrap();
    assert_eq!(
        again,
        ImportResult {
            added: 0,
            merged: 0,
            conflicts: 0,
            skipped: 2
        }
    );
    assert_eq!(v.items().len(), 3);
}

#[test]
fn different_password_merges_and_keeps_the_other_in_history() {
    let v = vault();
    v.upsert(login("GitHub", "https://github.com", "alice", "old"))
        .unwrap();
    let csv = "name,url,username,password\n\
               github.com,https://www.github.com/login,Alice,new\n\
               github.com,https://github.com/session,alice,old\n\
               github.com,https://github.com/session,alice,old\n";
    let b = batch(csv);
    let p = b.preview(v.clone());
    assert_eq!(p.groups.len(), 1);
    let g = &p.groups[0];
    assert_eq!(g.kind, ClashKind::Differs);
    assert_eq!(g.entries, [0, 1, 2]);
    assert!(g.differs.contains(&ClashField::Password));
    assert!(g.differs.contains(&ClashField::Urls));
    let ids: Vec<&str> = g.password_choices.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["existing", "import#0"]);
    // The export has no dates: the vault's password stays by default.
    assert!(g.password_choices[0].is_default);
    assert_eq!(g.default_decision, ImportDecision::default_merge());
    assert!(p.entries.iter().all(|e| e.action == ImportAction::Merge));
    assert_eq!(p.entries[0].adds, ["2 websites"]);
    let r = b.commit(v.clone()).unwrap();
    assert_eq!((r.added, r.merged, r.conflicts, r.skipped), (0, 3, 0, 0));
    let items = v.items();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].password, "old");
    assert_eq!(items[0].password_history.len(), 1);
    assert_eq!(items[0].password_history[0].password, "new");
    assert_eq!(items[0].urls.len(), 3);
    let again = batch(csv).preview(v.clone());
    assert_eq!(again.groups[0].kind, ClashKind::Identical);
    assert_eq!(again.groups[0].default_decision, ImportDecision::Skip);
    assert_eq!(again.duplicates, 3);
    let again = batch(csv).commit(v.clone()).unwrap();
    assert_eq!((again.added, again.merged, again.skipped), (0, 0, 3));
    assert_eq!(v.items().len(), 1);
}

#[test]
fn passkeys_attach_once() {
    let v = vault();
    let existing = v
        .upsert(login("WebAuthn", "https://webauthn.io", "kim", "wa-pass"))
        .unwrap();
    let (_, key_b64) = passkey_key();
    let export = bitwarden_export(&key_b64).to_string();
    let r = batch(&export).commit(v.clone()).unwrap();
    // WebAuthn.io merges (passkey + 2FA + custom field); note, card and "Bad passkey" are new.
    assert_eq!((r.added, r.merged), (3, 1));
    let item = v.get(existing.id.clone()).unwrap();
    assert_eq!(item.passkeys.len(), 1);
    assert!(item.has_totp());
    assert_eq!(v.find_passkeys("webauthn.io".into(), vec![]).len(), 1);
    let again = batch(&export).commit(v.clone()).unwrap();
    assert_eq!((again.added, again.merged), (0, 0));
    assert_eq!(v.find_passkeys("webauthn.io".into(), vec![]).len(), 1);
}

#[test]
fn notes_and_titled_logins_dedupe() {
    let v = vault();
    let csv = "Title,Username,Password,Notes\n\
               Laptop,me,pw,\n\
               ,,,\n";
    let b =
        ImportBatch::new(parse_import(csv.as_bytes(), "", Some(ImportFormat::GenericCsv)).unwrap());
    assert_eq!(b.commit(v.clone()).unwrap().added, 1);
    let b =
        ImportBatch::new(parse_import(csv.as_bytes(), "", Some(ImportFormat::GenericCsv)).unwrap());
    assert_eq!(b.preview(v.clone()).duplicates, 1);

    let notes = "title,note\nAlarm,1234\nAlarm,5678\n";
    let b = batch(notes);
    let p = b.preview(v.clone());
    assert_eq!(p.to_add, 2);
    b.commit(v.clone()).unwrap();
    assert_eq!(batch(notes).preview(v).duplicates, 2);
}

#[test]
fn preview_has_no_secrets() {
    let v = vault();
    let b =
        batch("name,url,username,password,note\nsite,https://site.test,u,TOPSECRET,NOTESECRET\n");
    let json = serde_json::to_string(&b.preview(v)).unwrap();
    assert!(
        !json.contains("TOPSECRET") && !json.contains("NOTESECRET"),
        "{json}"
    );
    assert!(json.contains("\"action\":\"add\""));
}

#[test]
fn iso_dates() {
    assert_eq!(iso8601_to_ms("1970-01-01T00:00:01Z"), 1000);
    assert_eq!(iso8601_to_ms("2024-03-01T10:00:00.000Z"), 1_709_287_200_000);
    assert_eq!(iso8601_to_ms("garbage"), 0);
    assert_eq!(epoch_to_ms(1_700_000_000), 1_700_000_000_000);
    assert_eq!(epoch_to_ms(1_700_000_000_000), 1_700_000_000_000);
}

#[test]
fn large_imports_are_planned_without_quadratic_url_parsing() {
    // Planning must not re-parse every vault item's URLs per imported entry (minutes on a phone).
    let mut csv = String::from("name,url,username,password\n");
    for i in 0..5000 {
        csv.push_str(&format!(
            "S{i},https://www.site{i}.example.com/login,user{i},pw{i}\n"
        ));
    }
    csv.push_str("S0 again,https://site0.example.com/other,USER0,pw0\n");
    let v = vault();
    let b = batch(&csv);
    let started = std::time::Instant::now();
    let preview = b.preview(v.clone());
    assert_eq!((preview.to_add, preview.to_merge), (5000, 1));
    let result = b.commit(v.clone()).unwrap();
    assert_eq!(result.added, 5000);
    let again = b.preview(v.clone());
    assert_eq!(again.duplicates, 5001);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "took {:?}",
        started.elapsed()
    );
}

fn batch_of(items: Vec<Item>) -> ImportBatch {
    ImportBatch::new(ImportReport {
        format: ImportFormat::GenericCsv,
        items,
        skipped: Vec::new(),
        warnings: Vec::new(),
    })
}

fn decide(group: &ImportGroup, decision: ImportDecision) -> ImportGroupDecision {
    ImportGroupDecision {
        group_id: group.id.clone(),
        decision,
    }
}

fn group_for<'a>(p: &'a ImportPreview, title: &str) -> &'a ImportGroup {
    p.groups
        .iter()
        .find(|g| g.title == title)
        .unwrap_or_else(|| panic!("no group {title}"))
}

/// Vault: GitHub (alice / gh-pw), GitLab (bob / gl-old). File: GitHub identical, GitLab with a new
/// password and a note, two rows for Example (carol, different passwords), one new login.
fn clash_setup() -> (Arc<Vault>, ImportBatch) {
    let v = vault();
    v.upsert(login("GitHub", "https://github.com", "alice", "gh-pw"))
        .unwrap();
    v.upsert(login("GitLab", "https://gitlab.com", "bob", "gl-old"))
        .unwrap();
    let mut gitlab = login(
        "GitLab.com",
        "https://gitlab.com/users/sign_in",
        "Bob",
        "gl-new",
    );
    gitlab.notes = "recovery: in the safe".into();
    let b = batch_of(vec![
        login("GitHub", "https://github.com", "alice", "gh-pw"),
        gitlab,
        login("Example", "https://example.com", "carol", "ex-1"),
        login(
            "Example 2",
            "https://www.example.com/login",
            "carol",
            "ex-2",
        ),
        login("New site", "https://new.example.org", "dave", "np"),
    ]);
    (v, b)
}

#[test]
fn clash_groups_and_defaults() {
    let (v, b) = clash_setup();
    let p = b.preview(v.clone());
    assert_eq!(p.clashes, 3);
    assert_eq!(p.groups.len(), 3);

    let gh = group_for(&p, "GitHub");
    assert_eq!(gh.kind, ClashKind::Identical);
    assert!(gh.differs.is_empty());
    assert_eq!(gh.default_decision, ImportDecision::Skip);
    assert!(gh.existing_id.is_some());
    assert!(gh.password_choices.is_empty());

    let gl = group_for(&p, "GitLab");
    assert_eq!(gl.kind, ClashKind::Differs);
    assert_eq!(
        gl.differs,
        [
            ClashField::Title,
            ClashField::Password,
            ClashField::Urls,
            ClashField::Notes
        ]
    );
    assert_eq!(gl.default_decision, ImportDecision::default_merge());
    let choices: Vec<(&str, MergeSource, bool)> = gl
        .password_choices
        .iter()
        .map(|c| (c.id.as_str(), c.source, c.is_default))
        .collect();
    assert_eq!(
        choices,
        [
            ("existing", MergeSource::Existing, true),
            ("import#1", MergeSource::Import, false)
        ]
    );
    assert!(gl.password_choices[0].modified_at > 0);
    assert_eq!(gl.password_choices[1].modified_at, 0);
    assert_eq!(gl.title_choices.len(), 2);

    let ex = group_for(&p, "Example");
    assert_eq!(ex.kind, ClashKind::InFileDuplicate);
    assert_eq!(ex.entries, [2, 3]);
    assert!(ex.existing_id.is_none());
    assert_eq!(ex.password_choices[0].id, "import#2");
    assert!(ex.password_choices[0].is_default);

    assert_eq!(p.entries[0].group.as_deref(), Some(gh.id.as_str()));
    assert_eq!(p.entries[0].action, ImportAction::Duplicate);
    assert_eq!(p.entries[1].action, ImportAction::Merge);
    assert_eq!(p.entries[1].adds, ["website", "notes"]);
    assert_eq!(p.entries[2].action, ImportAction::Add);
    assert_eq!(p.entries[3].action, ImportAction::Merge);
    assert_eq!(p.entries[4].action, ImportAction::Add);
    assert_eq!(p.entries[4].group, None);
    assert_eq!(
        (p.to_add, p.to_merge, p.duplicates, p.conflicts),
        (2, 2, 1, 0)
    );
    let again = b.preview(v.clone());
    let ids = |p: &ImportPreview| p.groups.iter().map(|g| g.id.clone()).collect::<Vec<_>>();
    assert_eq!(ids(&p), ids(&again));
}

#[test]
fn commit_with_defaults() {
    let (v, b) = clash_setup();
    let r = b.commit(v.clone()).unwrap();
    assert_eq!(
        r,
        ImportResult {
            added: 2,
            merged: 2,
            conflicts: 0,
            skipped: 1
        }
    );
    let items = v.items();
    assert_eq!(items.len(), 4, "{items:?}");
    let gl = items.iter().find(|i| i.username == "bob").unwrap();
    assert_eq!(gl.title, "GitLab");
    assert_eq!(gl.password, "gl-old");
    assert_eq!(
        gl.password_history
            .iter()
            .map(|h| h.password.as_str())
            .collect::<Vec<_>>(),
        ["gl-new"]
    );
    assert!(gl.password_history[0].replaced_at > 0);
    assert_eq!(gl.urls.len(), 2);
    assert_eq!(gl.notes, "recovery: in the safe");
    let ex: Vec<&Item> = items.iter().filter(|i| i.username == "carol").collect();
    assert_eq!(ex.len(), 1);
    assert_eq!(ex[0].title, "Example");
    assert_eq!(ex[0].password, "ex-1");
    assert_eq!(ex[0].password_history[0].password, "ex-2");
    assert_eq!(ex[0].urls.len(), 2);
}

#[test]
fn commit_with_decisions() {
    let (v, b) = clash_setup();
    let p = b.preview(v.clone());
    let gh = group_for(&p, "GitHub");
    let gl = group_for(&p, "GitLab");
    let ex = group_for(&p, "Example");
    let r = b
        .commit_with(
            v.clone(),
            vec![
                decide(gh, ImportDecision::KeepBoth),
                decide(
                    gl,
                    ImportDecision::Merge {
                        password_from: Some("import#1".into()),
                        totp_from: None,
                        title_from: Some("import#1".into()),
                    },
                ),
                decide(ex, ImportDecision::Skip),
                ImportGroupDecision {
                    group_id: "import#99".into(),
                    decision: ImportDecision::KeepBoth,
                },
            ],
        )
        .unwrap();
    assert_eq!(
        r,
        ImportResult {
            added: 2,
            merged: 1,
            conflicts: 1,
            skipped: 2
        }
    );
    let items = v.items();
    assert_eq!(
        items.iter().filter(|i| i.username == "alice").count(),
        2,
        "kept both"
    );
    assert!(items.iter().all(|i| i.username != "carol"), "skipped");
    let gl = items.iter().find(|i| i.username == "bob").unwrap();
    assert_eq!(gl.title, "GitLab.com");
    assert_eq!(gl.password, "gl-new");
    assert_eq!(gl.password_history[0].password, "gl-old");
    assert_eq!(gl.username, "bob", "the vault's username stays");
}

#[test]
fn skipping_a_differing_group_marks_its_entries() {
    let (v, b) = clash_setup();
    let p = b.preview(v.clone());
    let gl = group_for(&p, "GitLab").clone();
    let r = b
        .commit_with(v.clone(), vec![decide(&gl, ImportDecision::Skip)])
        .unwrap();
    assert_eq!(r.skipped, 2);
    let item = v.get(gl.existing_id.clone().unwrap()).unwrap();
    assert_eq!(item.password, "gl-old");
    assert!(item.password_history.is_empty());
    let (v, b) = clash_setup();
    let p = b.preview(v.clone());
    let ex = group_for(&p, "Example");
    let r = b
        .commit_with(v.clone(), vec![decide(ex, ImportDecision::KeepBoth)])
        .unwrap();
    assert_eq!((r.added, r.conflicts), (3, 1));
    assert_eq!(
        v.items().iter().filter(|i| i.username == "carol").count(),
        2
    );
}

#[test]
fn newest_known_password_wins_and_totp_is_kept_in_notes() {
    let v = vault();
    let mut existing = login("Shop", "https://shop.test", "me", "shop-old");
    existing.totp = Some(SECRET.into());
    let existing = v.upsert(existing).unwrap();
    let mut newer = login("Shop", "https://shop.test", "me", "shop-new");
    newer.updated_at = existing.updated_at + 60_000;
    newer.totp = Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
    newer.passkeys = vec![Passkey {
        credential_id: vec![1, 2, 3],
        rp_id: "shop.test".into(),
        ..Default::default()
    }];
    let b = batch_of(vec![newer]);
    let p = b.preview(v.clone());
    let g = &p.groups[0];
    assert_eq!(g.kind, ClashKind::Differs);
    assert_eq!(
        g.differs,
        [ClashField::Password, ClashField::Totp, ClashField::Passkeys]
    );
    assert!(g.password_choices[1].is_default, "the import is newer");
    assert!(g.totp_choices[1].is_default);
    b.commit_with(
        v.clone(),
        vec![decide(
            g,
            ImportDecision::Merge {
                password_from: None,
                totp_from: Some("existing".into()),
                title_from: None,
            },
        )],
    )
    .unwrap();
    let item = v.get(existing.id.clone()).unwrap();
    assert_eq!(item.password, "shop-new");
    assert_eq!(item.password_history[0].password, "shop-old");
    assert_eq!(item.totp.as_deref(), Some(SECRET));
    assert!(
        item.notes.starts_with("Previous 2FA secret (replaced ")
            && item.notes.ends_with(": GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        "{}",
        item.notes
    );
    assert_eq!(item.passkeys.len(), 1);
    // Importing the same entry again: its password is in the history, its 2FA in the notes.
    let again = batch_of(vec![{
        let mut i = login("Shop", "https://shop.test", "me", "shop-old");
        i.totp = Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
        i
    }])
    .preview(v.clone());
    assert_eq!(again.groups[0].kind, ClashKind::Identical);
}

#[test]
fn password_history_is_capped_deduplicated_and_sealed() {
    let v = vault();
    let mut item = login("Bank", "https://bank.test", "me", "current");
    item.password_history = (0..MAX_PASSWORD_HISTORY)
        .map(|n| PasswordHistoryEntry {
            password: format!("old{n}"),
            replaced_at: 1,
        })
        .collect();
    let item = v.upsert(item).unwrap();
    let b = batch_of(vec![
        login("Bank", "https://bank.test", "me", "newer"),
        login("Bank", "https://bank.test", "me", "current"),
    ]);
    let g = b.preview(v.clone()).groups[0].clone();
    b.commit_with(
        v.clone(),
        vec![decide(
            &g,
            ImportDecision::Merge {
                password_from: Some("import#0".into()),
                totp_from: None,
                title_from: None,
            },
        )],
    )
    .unwrap();
    let merged = v.get(item.id.clone()).unwrap();
    assert_eq!(merged.password, "newer");
    assert_eq!(merged.password_history.len(), MAX_PASSWORD_HISTORY);
    assert_eq!(merged.password_history[0].password, "current");
    assert_eq!(merged.password_history[1].password, "old0");
    let file = v.serialize().unwrap();
    let reopened = Vault::unlock(file, "pw".into(), "dev".into()).unwrap();
    assert_eq!(
        reopened.get(item.id.clone()).unwrap().password_history,
        merged.password_history
    );
    let plain = serde_json::to_string(&login("x", "https://x.test", "u", "p")).unwrap();
    assert!(!plain.contains("password_history"), "{plain}");
    let old: Item = serde_json::from_str(r#"{"title":"t","password":"p"}"#).unwrap();
    assert!(old.password_history.is_empty());
    assert!(!format!("{merged:?}").contains("old0"));
}

#[test]
fn clash_preview_has_no_secrets() {
    let v = vault();
    let mut e = login("Site", "https://site.test", "u", "VAULTSECRET");
    e.notes = "VAULTNOTE".into();
    e.totp = Some(SECRET.into());
    v.upsert(e).unwrap();
    let b = batch(
        "name,url,username,password,note,totp\n\
         site,https://site.test,u,TOPSECRET,NOTESECRET,GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n\
         other,https://other.test,o,OTHERSECRET1,,\n\
         other,https://other.test,o,OTHERSECRET2,,\n",
    );
    let p = b.preview(v.clone());
    assert_eq!(p.groups.len(), 2);
    let json = serde_json::to_string(&p).unwrap();
    for secret in [
        "VAULTSECRET",
        "VAULTNOTE",
        "TOPSECRET",
        "NOTESECRET",
        "OTHERSECRET",
        SECRET,
        "GEZDGNBVGY3TQOJQ",
    ] {
        assert!(!json.contains(secret), "{secret} in {json}");
    }
    let dups = serde_json::to_string(&find_duplicates(v)).unwrap();
    assert!(!dups.contains("VAULTSECRET"));
}

#[test]
fn decisions_as_json() {
    let d: ImportDecision =
        serde_json::from_str(r#"{"type":"merge","password_from":"import#3"}"#).unwrap();
    assert_eq!(
        d,
        ImportDecision::Merge {
            password_from: Some("import#3".into()),
            totp_from: None,
            title_from: None
        }
    );
    let d: ImportDecision = serde_json::from_str(r#"{"type":"keep_both"}"#).unwrap();
    assert_eq!(d, ImportDecision::KeepBoth);
    assert_eq!(
        serde_json::to_string(&ImportDecision::Skip).unwrap(),
        r#"{"type":"skip"}"#
    );
}

#[test]
fn dates_for_history() {
    assert_eq!(merge::ymd(0), "1970-01-01");
    assert_eq!(merge::ymd(1_709_287_200_000), "2024-03-01");
    assert_eq!(merge::ymd(951_782_400_000), "2000-02-29");
}

#[test]
fn find_and_merge_vault_duplicates() {
    let v = vault();
    let a = v
        .upsert(login("GitHub", "https://github.com", "alice", "pw-a"))
        .unwrap();
    let mut b_item = login(
        "github.com",
        "https://www.github.com/login",
        "Alice",
        "pw-b",
    );
    b_item.totp = Some(SECRET.into());
    let b_item = v.upsert(b_item).unwrap();
    // Same site, no username, same password; and the same password on another site (not a dup).
    let n1 = v
        .upsert(login("Router", "http://router.lan", "", "admin1"))
        .unwrap();
    let n2 = v
        .upsert(login("Router 2", "http://router.lan", "", "admin1"))
        .unwrap();
    v.upsert(login("NAS", "http://nas.lan", "", "admin1"))
        .unwrap();
    v.upsert(login(
        "GitHub work",
        "https://github.com",
        "alice-work",
        "pw-w",
    ))
    .unwrap();

    let groups = find_duplicates(v.clone());
    assert_eq!(groups.len(), 2, "{groups:?}");
    let gh = groups.iter().find(|g| g.title.contains("ithub")).unwrap();
    assert_eq!(gh.kind, ClashKind::Differs);
    assert_eq!(gh.item_ids, [b_item.id.clone(), a.id.clone()]);
    assert!(gh.differs.contains(&ClashField::Password));
    assert_eq!(gh.password_choices[0].id, b_item.id);
    assert!(gh.password_choices[0].is_default);
    assert_eq!(gh.items.len(), 2);
    let router = groups
        .iter()
        .find(|g| g.title.starts_with("Router"))
        .unwrap();
    assert_eq!(router.kind, ClashKind::Identical);
    assert_eq!(router.item_ids.len(), 2);

    assert!(
        merge_items(v.clone(), gh.item_ids.clone(), ImportDecision::Skip)
            .unwrap()
            .is_none()
    );
    assert_eq!(v.items().len(), 6);

    let merged = merge_items(
        v.clone(),
        gh.item_ids.clone(),
        ImportDecision::Merge {
            password_from: Some(a.id.clone()),
            totp_from: None,
            title_from: Some(a.id.clone()),
        },
    )
    .unwrap()
    .unwrap();
    assert_eq!(merged.id, b_item.id);
    assert_eq!(merged.title, "GitHub");
    assert_eq!(merged.password, "pw-a");
    assert_eq!(merged.password_history[0].password, "pw-b");
    assert!(merged.has_totp());
    assert_eq!(merged.urls.len(), 2);
    assert!(v.get(a.id.clone()).is_none(), "the other copy is deleted");

    let router = merge_items(
        v.clone(),
        router.item_ids.clone(),
        ImportDecision::default_merge(),
    )
    .unwrap()
    .unwrap();
    assert!(router.password_history.is_empty());
    assert!([n1.id.clone(), n2.id.clone()].contains(&router.id));
    assert_eq!(v.items().len(), 4);
    assert!(find_duplicates(v.clone()).is_empty());

    assert!(merge_items(
        v.clone(),
        vec![router.id.clone()],
        ImportDecision::default_merge()
    )
    .is_err());
    assert!(merge_items(
        v.clone(),
        vec![router.id.clone(), "nope".into()],
        ImportDecision::default_merge()
    )
    .is_err());
}

#[test]
fn bitwarden_json_cards_identities_and_folders() {
    let v = json!({"encrypted": false,
        "folders": [{"id": "f1", "name": "Finance"}],
        "collections": [{"id": "c1", "name": "Family"}],
        "items": [
        {"type": 3, "name": "My Visa", "folderId": "f1", "collectionIds": ["c1"], "notes": "main card",
         "card": {"cardholderName": "Ada Lovelace", "brand": "Visa", "number": "4111 1111 1111 1111",
                  "expMonth": "7", "expYear": "2031", "code": "123"},
         "fields": [{"name": "Bank", "value": "Example Bank", "type": 0},
                    {"name": "Online banking", "value": true, "type": 2}]},
        {"type": 4, "name": "Me", "identity": {"title": "Ms", "firstName": "Ada", "middleName": "", "lastName": "Lovelace",
            "address1": "1 Main St", "address2": null, "address3": null, "city": "London", "state": "", "postalCode": "N1",
            "country": "GB", "company": "Engines Ltd", "email": "ada@example.com", "phone": "+44 1", "ssn": "123-45-6789",
            "username": "ada", "passportNumber": null, "licenseNumber": null}}
    ]});
    let r = parse(&v.to_string(), "bitwarden.json");
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    let card = find(&r, "My Visa");
    assert_eq!(card.kind, ItemKind::Card);
    assert_eq!(card.tags, ["Finance", "Family"]);
    assert_eq!(card.notes, "main card");
    let data = card.card.as_ref().unwrap();
    assert_eq!(
        (
            data.cardholder_name.as_str(),
            data.expiry_month,
            data.expiry_year,
            data.security_code.as_str(),
            data.brand.as_str()
        ),
        ("Ada Lovelace", 7, 2031, "123", "visa")
    );
    assert_eq!(card.fields.len(), 2);
    assert_eq!(card.fields[1].value, "true");
    let me = find(&r, "Me");
    assert_eq!(me.kind, ItemKind::Identity);
    let id = me.identity.as_ref().unwrap();
    assert_eq!(id.full_name(), "Ada Lovelace");
    assert_eq!(
        (id.email.as_str(), id.city.as_str(), id.company.as_str()),
        ("ada@example.com", "London", "Engines Ltd")
    );
    let ssn = me
        .fields
        .iter()
        .find(|f| f.name == "Social security number")
        .unwrap();
    assert_eq!(ssn.kind, FieldKind::Hidden);
    assert!(me
        .fields
        .iter()
        .any(|f| f.name == "Username" && f.value == "ada"));

    let v = vault();
    let report = parse(
        &json!({"encrypted": false, "items": [
            {"type": 3, "name": "My Visa", "card": {"number": "4111 1111 1111 1111", "expMonth": 7, "expYear": 2031}}
        ]})
        .to_string(),
        "bw.json",
    );
    let first = ImportBatch::new(report.clone()).commit(v.clone()).unwrap();
    assert_eq!(first.added, 1);
    let saved = &v.items()[0];
    assert_eq!(saved.card.as_ref().unwrap().number, "4111111111111111");
    let again = ImportBatch::new(report).preview(v.clone());
    assert_eq!(again.duplicates, 1);
    // The same card with a security code is the same card, with something new.
    let more = parse(
        &json!({"encrypted": false, "items": [
            {"type": 3, "name": "Visa card", "card": {"number": "4111111111111111", "code": "999"}}
        ]})
        .to_string(),
        "bw.json",
    );
    let preview = ImportBatch::new(more.clone()).preview(v.clone());
    assert_eq!(preview.groups.len(), 1);
    assert_eq!(preview.groups[0].kind, ClashKind::Differs);
    ImportBatch::new(more).commit(v.clone()).unwrap();
    assert_eq!(v.items().len(), 1);
    let card = v.items()[0].card.clone().unwrap();
    assert_eq!(
        (card.security_code.as_str(), card.expiry_year),
        ("999", 2031)
    );
}

#[test]
fn proton_pass_cards_identities_and_vault_tags() {
    let data = json!({"version": "1.21.2", "encrypted": false, "vaults": {
        "s1": {"name": "Personal", "items": [
            {"itemId": "c", "state": 1, "data": {"metadata": {"name": "Debit", "note": ""}, "type": "creditCard",
                "extraFields": [],
                "content": {"cardholderName": "Leo", "cardType": 0, "number": "5555555555554444",
                    "verificationNumber": "321", "expirationDate": "2027-03", "pin": "4242"}}}]},
        "s2": {"name": "Work", "items": [
            {"itemId": "i", "state": 1, "data": {"metadata": {"name": "Work identity", "note": ""}, "type": "identity",
                "extraFields": [],
                "content": {"fullName": "Leo Proton", "email": "leo@work.example", "phoneNumber": "123",
                    "streetAddress": "Rue 1", "city": "Geneva", "zipOrPostalCode": "1200", "countryOrRegion": "CH",
                    "organization": "Proton", "birthdate": "1990-01-02", "passportNumber": "X123",
                    "extraPersonalDetails": [{"fieldName": "Nickname", "type": "text", "data": {"content": "Leo P"}}]}}}]}
    }})
    .to_string();
    let r = parse(&data, "data.json");
    let card = find(&r, "Debit");
    assert_eq!(card.kind, ItemKind::Card);
    assert_eq!(card.tags, ["Personal"]);
    let c = card.card.as_ref().unwrap();
    assert_eq!(
        (
            c.expiry_month,
            c.expiry_year,
            c.pin.as_str(),
            c.security_code.as_str()
        ),
        (3, 2027, "4242", "321")
    );
    let me = find(&r, "Work identity");
    assert_eq!(me.tags, ["Work"]);
    let id = me.identity.as_ref().unwrap();
    assert_eq!(
        (
            id.first_name.as_str(),
            id.last_name.as_str(),
            id.birth_date.as_str()
        ),
        ("Leo", "Proton", "1990-01-02")
    );
    assert_eq!(id.postal_code, "1200");
    assert!(me
        .fields
        .iter()
        .any(|f| f.name == "Passport number" && f.kind == FieldKind::Hidden));
    assert!(me
        .fields
        .iter()
        .any(|f| f.name == "Nickname" && f.value == "Leo P"));
}

#[test]
fn onepassword_cards_identities_and_tags() {
    let data = json!({"accounts": [{"attrs": {"name": "Me"}, "vaults": [
        {"attrs": {"name": "Private"}, "items": [
            {"uuid": "c", "state": "active", "categoryUuid": "002", "overview": {"title": "Amex", "tags": ["money"]},
             "details": {"sections": [{"title": "", "fields": [
                {"title": "cardholder name", "id": "cardholder", "value": {"string": "Mia"}},
                {"title": "type", "id": "type", "value": {"creditCardType": "amex"}},
                {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "378282246310005"}},
                {"title": "verification number", "id": "cvv", "value": {"concealed": "1234"}},
                {"title": "expiry date", "id": "expiry", "value": {"monthYear": 202912}},
                {"title": "issuing bank", "id": "bank", "value": {"string": "AmEx Bank"}}]}]}},
            {"uuid": "i", "state": "active", "categoryUuid": "004", "overview": {"title": "Mia"},
             "details": {"sections": [{"title": "Identification", "fields": [
                {"title": "first name", "id": "firstname", "value": {"string": "Mia"}},
                {"title": "last name", "id": "lastname", "value": {"string": "Smith"}},
                {"title": "birth date", "id": "birthdate", "value": {"date": 631152000}},
                {"title": "occupation", "id": "occupation", "value": {"string": "Pilot"}}]},
                {"title": "Address", "fields": [
                {"title": "address", "id": "address", "value": {"address": {"street": "5 Elm", "city": "Austin",
                    "country": "us", "zip": "73301", "state": "TX"}}},
                {"title": "email", "id": "email", "value": {"email": {"email_address": "mia@example.com", "provider": null}}}]}]}}
        ]},
        {"attrs": {"name": "Shared"}, "items": [
            {"uuid": "n", "state": "active", "categoryUuid": "003", "overview": {"title": "Wifi"},
             "details": {"notesPlain": "pw"}}]}
    ]}]})
    .to_string();
    let r = parse(&data, "export.data");
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    let amex = find(&r, "Amex");
    assert_eq!(amex.tags, ["Private", "money"]);
    let c = amex.card.as_ref().unwrap();
    assert_eq!(
        (
            c.cardholder_name.as_str(),
            c.number.as_str(),
            c.security_code.as_str(),
            c.expiry_month,
            c.expiry_year,
            c.brand.as_str()
        ),
        ("Mia", "378282246310005", "1234", 12, 2029, "amex")
    );
    assert_eq!(amex.fields[0].value, "AmEx Bank");
    let mia = find(&r, "Mia");
    let id = mia.identity.as_ref().unwrap();
    assert_eq!(id.full_name(), "Mia Smith");
    assert_eq!(id.birth_date, "1990-01-01");
    assert_eq!((id.city.as_str(), id.region.as_str()), ("Austin", "TX"));
    assert_eq!(id.email, "mia@example.com");
    assert_eq!(mia.fields[0].value, "Pilot");
    assert_eq!(find(&r, "Wifi").tags, ["Shared"]);
}

#[test]
fn lastpass_card_and_address_notes() {
    let csv = "url,username,password,totp,extra,name,grouping,fav\n\
               http://sn,,,,\"NoteType:Credit Card\nLanguage:en-US\nName on Card:Gina\nType:Visa\nNumber:4012888888881881\nSecurity Code:456\nStart Date:,\nExpiration Date:January,2028\nNotes:line one\nline two\",Visa,Money\\Cards,0\n\
               http://sn,,,,\"NoteType:Address\nLanguage:en-US\nTitle:ms\nFirst Name:Gina\nMiddle Name:\nLast Name:Lp\nUsername:gina\nBirthday:,,\nCompany:Acme\nAddress 1:9 Road\nCity / Town:Paris\nZip / Postal Code:75001\nCountry:FR\nEmail Address:g@example.com\nPhone:{\"\"num\"\":\"\"555\"\",\"\"ext\"\":\"\"\"\",\"\"cc3l\"\":\"\"FRA\"\"}\nNotes:\",Home,,0\n";
    let r = parse(csv, "lastpass_export.csv");
    let visa = find(&r, "Visa");
    assert_eq!(visa.kind, ItemKind::Card);
    assert_eq!(visa.tags, ["Money/Cards"]);
    assert_eq!(visa.notes, "line one\nline two");
    let c = visa.card.as_ref().unwrap();
    assert_eq!(
        (c.cardholder_name.as_str(), c.expiry_month, c.expiry_year),
        ("Gina", 1, 2028)
    );
    let home = find(&r, "Home");
    assert_eq!(home.kind, ItemKind::Identity);
    let id = home.identity.as_ref().unwrap();
    assert_eq!(
        (id.phone.as_str(), id.city.as_str(), id.birth_date.as_str()),
        ("555", "Paris", "")
    );
}

#[test]
fn dashlane_payments_and_personal_info() {
    let payments = "type,account_name,account_holder,cc_number,code,expiration_month,expiration_year,routing_number,account_number,country,issuing_bank,note,name\n\
                    payment_card,Travel card,Henry,4111111111111111,111,05,2030,,,,,,\n\
                    bank,Checking,Henry,,,,,021000021,123456789,US,Big Bank,,\n";
    let personal = "type,title,first_name,middle_name,last_name,login,date_of_birth,place_of_birth,email,email_type,item_name,phone_number,address,city,state,country,zip,address_recipient,address_building,address_apartment,address_floor,address_door,job_title,url\n\
                    name,Mr,Henry,,Dash,,1980-05-05,Rome,,,,,,,,,,,,,,,,\n\
                    email,,,,,,,,henry@example.com,,,,,,,,,,,,,,,\n\
                    email,,,,,,,,other@example.com,,,,,,,,,,,,,,,\n";
    let data = zip(&[("payments.csv", payments), ("personalInfo.csv", personal)]);
    let r = parse_import(&data, "dashlane.zip", None).unwrap();
    let card = find(&r, "Travel card");
    assert_eq!(card.kind, ItemKind::Card);
    let c = card.card.as_ref().unwrap();
    assert_eq!((c.expiry_month, c.expiry_year), (5, 2030));
    let bank = find(&r, "Checking");
    assert_eq!(bank.kind, ItemKind::Note);
    assert!(bank
        .fields
        .iter()
        .any(|f| f.name == "Account number" && f.kind == FieldKind::Hidden));
    let me = find(&r, "Dashlane personal info");
    let id = me.identity.as_ref().unwrap();
    assert_eq!(id.full_name(), "Henry Dash");
    assert_eq!(id.email, "henry@example.com");
    assert!(me.fields.iter().any(|f| f.value == "other@example.com"));
}

#[test]
fn identities_match_by_name_and_merge_tags_and_fields() {
    let v = vault();
    v.upsert(Item {
        kind: ItemKind::Identity,
        title: "Me".into(),
        identity: Some(IdentityData {
            first_name: "Ada".into(),
            email: "ada@example.com".into(),
            ..Default::default()
        }),
        tags: vec!["Personal".into()],
        ..Default::default()
    })
    .unwrap();
    let mut item = Item {
        kind: ItemKind::Identity,
        title: "Me".into(),
        identity: Some(IdentityData {
            first_name: "Ada".into(),
            email: "ada@example.com".into(),
            phone: "123".into(),
            ..Default::default()
        }),
        tags: vec!["personal".into(), "Forms".into()],
        fields: vec![CustomField {
            name: "Nickname".into(),
            value: "A".into(),
            kind: FieldKind::Text,
        }],
        ..Default::default()
    };
    let report = ImportReport {
        format: ImportFormat::PassybleJson,
        items: vec![item.clone()],
        skipped: vec![],
        warnings: vec![],
    };
    let result = ImportBatch::new(report.clone()).commit(v.clone()).unwrap();
    assert_eq!(result.merged, 1);
    let merged = &v.items()[0];
    assert_eq!(merged.tags, ["Personal", "Forms"]);
    assert_eq!(merged.identity.as_ref().unwrap().phone, "123");
    assert_eq!(merged.fields.len(), 1);
    assert_eq!(ImportBatch::new(report).preview(v.clone()).duplicates, 1);
    item.identity.as_mut().unwrap().first_name = "Bob".into();
    let other = ImportReport {
        format: ImportFormat::PassybleJson,
        items: vec![item],
        skipped: vec![],
        warnings: vec![],
    };
    assert_eq!(ImportBatch::new(other).commit(v.clone()).unwrap().added, 1);
    let blank = Item {
        kind: ItemKind::Card,
        title: "Gift card".into(),
        card: Some(CardData::default()),
        ..Default::default()
    };
    v.upsert(blank.clone()).unwrap();
    let report = ImportReport {
        format: ImportFormat::PassybleJson,
        items: vec![blank],
        skipped: vec![],
        warnings: vec![],
    };
    assert_eq!(ImportBatch::new(report).preview(v).duplicates, 1);
}

#[test]
fn expiry_spellings() {
    for (input, want) in [
        ("07/31", (7, 2031)),
        ("7/2031", (7, 2031)),
        ("2031-07", (7, 2031)),
        ("203107", (7, 2031)),
        ("0731", (7, 2031)),
        ("July,2031", (7, 2031)),
        ("13/2031", (0, 2031)),
        ("", (0, 0)),
    ] {
        assert_eq!(parse_expiry(input), want, "{input}");
    }
    assert_eq!(brand_id("American Express"), "amex");
    assert_eq!(brand_id("MasterCard"), "mastercard");
}
