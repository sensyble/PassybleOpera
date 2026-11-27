//! Cards, identities, custom fields, tags, the trash, export and password health, through the
//! public API.

use pass_core::*;
use std::sync::Arc;

fn fast_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
        ..Default::default()
    }
}

fn new_vault(device: &str) -> Arc<Vault> {
    Vault::create_with_kdf("correct horse", device, fast_kdf()).unwrap()
}

fn login(title: &str, url: &str, user: &str, password: &str) -> Item {
    Item {
        title: title.into(),
        username: user.into(),
        password: password.into(),
        urls: vec![url.into()],
        ..Default::default()
    }
}

const NUMBER: &str = "4111 1111 1111 1111";

fn card() -> Item {
    Item {
        kind: ItemKind::Card,
        title: "".into(),
        card: Some(CardData {
            cardholder_name: "Ada Lovelace".into(),
            number: NUMBER.into(),
            expiry_month: 7,
            expiry_year: 31,
            security_code: "987".into(),
            pin: "2468".into(),
            ..Default::default()
        }),
        tags: vec![" Finance ".into(), "finance".into(), "".into()],
        ..Default::default()
    }
}

fn identity() -> Item {
    Item {
        kind: ItemKind::Identity,
        title: "Me".into(),
        identity: Some(IdentityData {
            first_name: "Ada".into(),
            last_name: "Lovelace".into(),
            email: "ada@example.com".into(),
            company: "Engines".into(),
            city: "London".into(),
            birth_date: "1815-12-10".into(),
            ..Default::default()
        }),
        tags: vec!["Personal/Forms".into()],
        ..Default::default()
    }
}

fn ids<T>(found: Vec<T>, id: impl Fn(&T) -> &str) -> Vec<String> {
    found.iter().map(|x| id(x).to_string()).collect()
}

#[test]
fn cards_are_normalised_and_never_leak_their_number() {
    let vault = new_vault("d");
    let saved = vault.upsert(card()).unwrap();
    let c = saved.card.clone().unwrap();
    assert_eq!(c.number, "4111111111111111");
    assert_eq!((c.brand.as_str(), c.expiry_year), ("visa", 2031));
    assert_eq!(saved.title, "Visa •••• 1111", "a default title");
    assert_eq!(saved.tags, ["Finance"]);
    assert!(card_number_valid(NUMBER.into()));
    assert!(!card_number_valid("4111 1111 1111 1112".into()));
    assert_eq!(card_brand("3782 822463 10005".into()), "amex");
    assert_eq!(card_brand("5555555555554444".into()), "mastercard");
    assert_eq!(card_brand("2223000048400011".into()), "mastercard");
    assert_eq!(card_brand("6011111111111117".into()), "discover");
    assert_eq!(card_brand("3530111333300000".into()), "jcb");
    assert_eq!(card_brand("2200000000000004".into()), "mir");
    assert_eq!(card_brand("".into()), "");

    // Card fields are kept only on a card item.
    let note = vault
        .upsert(Item {
            kind: ItemKind::Note,
            tags: vec![],
            ..card()
        })
        .unwrap();
    assert!(note.card.is_none());
    assert!(vault
        .upsert(Item {
            card: Some(CardData {
                expiry_month: 13,
                ..Default::default()
            }),
            ..card()
        })
        .is_err());

    // Summaries: brand, last four, expiry; never the number, code or PIN.
    let summaries = vault.summaries();
    let summary = summaries.iter().find(|s| s.id == saved.id).unwrap();
    let cs = summary.card.clone().unwrap();
    assert_eq!(
        (
            cs.last4.as_str(),
            cs.brand.as_str(),
            cs.expiry_month,
            cs.expiry_year
        ),
        ("1111", "visa", 7, 2031)
    );
    let dump = format!("{summaries:?}");
    for secret in ["4111111111111111", "411111", "987", "2468"] {
        assert!(!dump.contains(secret), "{secret} in {dump}");
    }
    assert!(!format!("{saved:?}").contains("4111111111111111"));

    // Search by title, cardholder, last four; the full number finds nothing.
    for query in ["visa", "lovelace", "1111", "tag:finance"] {
        assert_eq!(
            ids(summaries_search(summaries.clone(), query.into()), |s| &s.id),
            [saved.id.as_str()],
            "{query}"
        );
        assert_eq!(
            ids(vault.search(query.into()), |i| &i.id),
            [saved.id.as_str()]
        );
    }
    assert!(summaries_search(summaries.clone(), "4111111111111111".into()).is_empty());
    assert!(vault.search("4111111111111111".into()).is_empty());
    assert!(vault.search("987".into()).is_empty(), "no security code");

    // Cards and identities never fill passwords.
    assert!(vault.find_for_url("https://visa.com".into()).is_empty());
}

#[test]
fn identities_custom_fields_and_tags() {
    let vault = new_vault("d");
    let me = vault.upsert(identity()).unwrap();
    let gh = vault
        .upsert(Item {
            fields: vec![
                CustomField {
                    name: "Recovery email".into(),
                    value: "backup@example.com".into(),
                    kind: FieldKind::Text,
                },
                CustomField {
                    name: "PIN".into(),
                    value: "778899".into(),
                    kind: FieldKind::Hidden,
                },
                CustomField::default(),
            ],
            tags: vec!["Work".into(), "Personal".into()],
            ..login("GitHub", "https://github.com", "octo", "pw-1")
        })
        .unwrap();
    assert_eq!(gh.fields.len(), 2, "the empty field is dropped");
    let work = vault
        .upsert(Item {
            tags: vec!["work/Clients".into()],
            ..login("CRM", "https://crm.example", "me", "pw-2")
        })
        .unwrap();

    let summaries = vault.summaries();
    let s = summaries.iter().find(|s| s.id == me.id).unwrap();
    let is = s.identity.clone().unwrap();
    assert_eq!(
        (
            is.full_name.as_str(),
            is.email.as_str(),
            is.company.as_str()
        ),
        ("Ada Lovelace", "ada@example.com", "Engines")
    );
    assert!(summaries.iter().find(|s| s.id == gh.id).unwrap().has_fields);
    assert!(!format!("{summaries:?}").contains("778899"));

    // Search: identity name / email; custom field names and visible values while unlocked, never
    // hidden values.
    assert_eq!(
        ids(vault.search("lovelace".into()), |i| &i.id),
        [me.id.as_str()]
    );
    assert_eq!(
        ids(vault.search("engines".into()), |i| &i.id),
        [me.id.as_str()]
    );
    assert_eq!(
        ids(vault.search("backup".into()), |i| &i.id),
        [gh.id.as_str()]
    );
    assert!(vault.search("778899".into()).is_empty());

    let tags = vault.tags();
    let pairs: Vec<(String, u32)> = tags.iter().map(|t| (t.tag.clone(), t.count)).collect();
    assert_eq!(
        pairs,
        [
            ("Personal".to_string(), 1),
            ("Personal/Forms".to_string(), 1),
            ("Work".to_string(), 1),
            ("work/Clients".to_string(), 1)
        ]
    );
    assert_eq!(summaries_tags(summaries.clone()), tags);
    assert_eq!(
        ids(vault.items_with_tag("WORK".into()), |i| &i.id),
        [work.id.clone(), gh.id.clone()]
    );
    assert_eq!(
        ids(
            summaries_with_tag(summaries.clone(), "personal".into()),
            |s| &s.id
        ),
        [gh.id.clone(), me.id.clone()]
    );
    assert!(summaries_with_tag(summaries.clone(), "Wor".into()).is_empty());
    assert_eq!(
        ids(
            summaries_search(summaries.clone(), "#work/clients".into()),
            |s| &s.id
        ),
        [work.id.as_str()]
    );
    assert_eq!(
        ids(
            summaries_search(summaries.clone(), "tag:work git".into()),
            |s| &s.id
        ),
        [gh.id.as_str()]
    );
    assert_eq!(
        ids(summaries_search(summaries, "forms".into()), |s| &s.id),
        [me.id.as_str()]
    );
}

#[test]
fn trash_hides_restores_and_purges() {
    let laptop = new_vault("laptop");
    let mut with_passkey = login("Site", "https://site.example", "kim", "pw");
    with_passkey.android_apps = vec![AndroidApp {
        package: "com.site".into(),
        cert_sha256: None,
        ..Default::default()
    }];
    with_passkey.passkeys = vec![Passkey {
        credential_id: vec![1, 2, 3],
        rp_id: "site.example".into(),
        user_name: "kim".into(),
        ..Default::default()
    }];
    let a = laptop.upsert(with_passkey).unwrap();
    let b = laptop
        .upsert(login("Other", "https://other.example", "x", "pw"))
        .unwrap();
    let base = laptop.serialize().unwrap();
    let phone = Vault::unlock(base, "correct horse".into(), "phone".into()).unwrap();

    laptop.delete(a.id.clone()).unwrap();
    assert!(laptop.get(a.id.clone()).is_none());
    assert_eq!(ids(laptop.items(), |i| &i.id), [b.id.as_str()]);
    assert_eq!(laptop.item_count(), 1);
    assert!(laptop.summaries().iter().all(|s| s.id != a.id));
    assert!(laptop.search("site".into()).is_empty());
    assert!(laptop
        .find_for_url("https://site.example".into())
        .is_empty());
    assert!(laptop
        .find_for_android_app("com.site".into(), None)
        .is_empty());
    assert!(laptop
        .find_passkeys("site.example".into(), vec![])
        .is_empty());
    assert!(laptop.record_use(a.id.clone(), 1).is_err());
    assert!(matches!(
        laptop.delete(a.id.clone()),
        Err(PassError::NotFound(_))
    ));
    let trash = laptop.trashed_items();
    assert_eq!(ids(trash.clone(), |i| &i.id), [a.id.as_str()]);
    let trashed_at = trash[0].trashed_at.unwrap();
    assert!(trashed_at > 0);
    let summaries = laptop.trash_summaries();
    assert_eq!(summaries[0].trashed_at, Some(trashed_at));
    assert!(laptop.summaries().iter().all(|s| s.trashed_at.is_none()));

    // Trashing is an item update: it syncs as one and converges.
    let stats = phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert_eq!((stats.updated, stats.deleted), (1, 0));
    assert!(phone.get(a.id.clone()).is_none());
    laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    assert_eq!(laptop.trashed_items(), phone.trashed_items());

    // Restore on the phone wins (newer) everywhere.
    std::thread::sleep(std::time::Duration::from_millis(2));
    let restored = phone.restore(a.id.clone()).unwrap();
    assert!(restored.trashed_at.is_none());
    assert!(matches!(
        phone.restore(a.id.clone()),
        Err(PassError::NotFound(_))
    ));
    laptop.merge_remote(phone.serialize().unwrap()).unwrap();
    assert_eq!(laptop.get(a.id.clone()).unwrap().passkeys.len(), 1);
    assert_eq!(laptop.find_passkeys("site.example".into(), vec![]).len(), 1);

    // purge needs the trash; delete_permanently doesn't.
    assert!(matches!(
        laptop.purge(a.id.clone()),
        Err(PassError::NotFound(_))
    ));
    laptop.delete(a.id.clone()).unwrap();
    laptop.purge(a.id.clone()).unwrap();
    assert!(laptop.trashed_items().is_empty());
    let stats = phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert_eq!(stats.deleted, 1);
    assert!(phone.trashed_items().is_empty() && phone.get(a.id.clone()).is_none());

    laptop.delete_permanently(b.id.clone()).unwrap();
    assert!(matches!(
        laptop.delete_permanently(b.id.clone()),
        Err(PassError::NotFound(_))
    ));

    let c = laptop
        .upsert(login("C", "https://c.example", "c", "p"))
        .unwrap();
    let d = laptop
        .upsert(login("D", "https://d.example", "d", "p"))
        .unwrap();
    laptop.delete(c.id.clone()).unwrap();
    laptop.delete(d.id.clone()).unwrap();
    assert_eq!(laptop.empty_trash(), 2);
    assert!(laptop.trashed_items().is_empty());
    assert_eq!(laptop.empty_trash(), 0);
}

#[test]
fn password_changes_are_dated() {
    let vault = new_vault("d");
    let saved = vault
        .upsert(login("A", "https://a.example", "a", "one"))
        .unwrap();
    assert!(saved.password_changed_at > 0);
    std::thread::sleep(std::time::Duration::from_millis(2));
    let renamed = vault
        .upsert(Item {
            title: "A2".into(),
            ..saved.clone()
        })
        .unwrap();
    assert_eq!(renamed.password_changed_at, saved.password_changed_at);
    std::thread::sleep(std::time::Duration::from_millis(2));
    let changed = vault
        .upsert(Item {
            password: "two".into(),
            ..renamed.clone()
        })
        .unwrap();
    assert!(changed.password_changed_at > saved.password_changed_at);
    // Trashing and restoring don't count as a change.
    vault.delete(saved.id.clone()).unwrap();
    let back = vault.restore(saved.id.clone()).unwrap();
    assert_eq!(back.password_changed_at, changed.password_changed_at);
}

#[test]
fn a_replaced_password_goes_to_the_history() {
    let vault = new_vault("h");
    let saved = vault
        .upsert(login("A", "https://a.example", "a", "one"))
        .unwrap();
    assert!(saved.password_history.is_empty());
    // A rename keeps the history as it is.
    let renamed = vault
        .upsert(Item {
            title: "A2".into(),
            ..saved.clone()
        })
        .unwrap();
    assert!(renamed.password_history.is_empty());
    let changed = vault
        .upsert(Item {
            password: "two".into(),
            ..renamed
        })
        .unwrap();
    let passwords = |item: &Item| -> Vec<String> {
        item.password_history
            .iter()
            .map(|h| h.password.clone())
            .collect()
    };
    assert_eq!(passwords(&changed), ["one"]);
    assert!(changed.password_history[0].replaced_at > 0);
    // An old copy saved back (an undo) keeps the password it replaces too.
    let undone = vault
        .upsert(Item {
            password: "one".into(),
            password_history: Vec::new(),
            ..changed.clone()
        })
        .unwrap();
    assert_eq!(passwords(&undone), ["two"]);
    // A password the caller's copy already has in its history isn't added twice.
    let merged = vault
        .upsert(Item {
            password: "three".into(),
            password_history: vec![PasswordHistoryEntry {
                password: "one".into(),
                replaced_at: 5,
            }],
            ..undone
        })
        .unwrap();
    assert_eq!(passwords(&merged), ["one"]);
    assert_eq!(merged.password_history[0].replaced_at, 5);
    // Newest first, at most MAX_PASSWORD_HISTORY: the oldest is dropped.
    let mut last = merged;
    for n in 0..MAX_PASSWORD_HISTORY + 2 {
        last = vault
            .upsert(Item {
                password: format!("p{n}"),
                ..last
            })
            .unwrap();
    }
    assert_eq!(last.password_history.len(), MAX_PASSWORD_HISTORY);
    assert_eq!(
        last.password_history[0].password,
        format!("p{}", MAX_PASSWORD_HISTORY)
    );
    // Clearing the password keeps the old one too.
    let cleared = vault
        .upsert(Item {
            password: String::new(),
            ..last.clone()
        })
        .unwrap();
    assert_eq!(cleared.password_history[0].password, last.password);
}

fn strip(mut item: Item) -> Item {
    item.id.clear();
    item.updated_at = 0;
    item
}

/// The items without ids and versions, as JSON (so a failure shows the difference).
fn sorted(mut items: Vec<Item>) -> Vec<serde_json::Value> {
    items.sort_by(|a, b| a.title.cmp(&b.title));
    items
        .into_iter()
        .map(|i| serde_json::to_value(strip(i)).unwrap())
        .collect()
}

/// A vault with one of everything.
fn full_vault() -> Arc<Vault> {
    let vault = new_vault("d");
    let created = passkey_create(
        "webauthn.io".into(),
        Some("WebAuthn".into()),
        vec![1, 2, 3],
        "kim".into(),
        "Kim".into(),
        vec![0; 32],
        vec![],
    )
    .unwrap();
    vault
        .upsert(Item {
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            passkeys: vec![created.passkey],
            notes: "line 1\nline \"2\", with comma".into(),
            favorite: true,
            password_history: vec![PasswordHistoryEntry {
                password: "older".into(),
                replaced_at: 1_700_000_000_000,
            }],
            android_apps: vec![AndroidApp {
                package: "io.webauthn".into(),
                cert_sha256: Some("AB:CD".into()),
                ..Default::default()
            }],
            fields: vec![
                CustomField {
                    name: "Security question".into(),
                    value: "pet".into(),
                    kind: FieldKind::Text,
                },
                CustomField {
                    name: "Backup".into(),
                    value: "1111-2222".into(),
                    kind: FieldKind::Hidden,
                },
            ],
            tags: vec!["Work".into(), "Dev".into()],
            ..login("WebAuthn", "https://webauthn.io", "kim", "pw,with\"quotes")
        })
        .unwrap();
    vault
        .upsert(Item {
            kind: ItemKind::Note,
            title: "Note".into(),
            notes: "secret note".into(),
            ..Default::default()
        })
        .unwrap();
    vault.upsert(card()).unwrap();
    vault.upsert(identity()).unwrap();
    let gone = vault
        .upsert(login("Trashed", "https://t.example", "t", "t"))
        .unwrap();
    vault.delete(gone.id).unwrap();
    vault
}

#[test]
fn passyble_json_export_round_trips() {
    let vault = full_vault();
    let json = export_json(vault.clone());
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["format"], "passyble-export");
    assert_eq!(parsed["version"], 1);
    assert_eq!(parsed["items"].as_array().unwrap().len(), 4, "no trash");
    let kinds: Vec<&str> = parsed["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"card") && kinds.contains(&"identity"));

    let report = parse_import(json.as_bytes(), "passyble-export.json", None).unwrap();
    assert_eq!(report.format, ImportFormat::PassybleJson);
    assert!(report.skipped.is_empty() && report.warnings.is_empty());
    let fresh = new_vault("other");
    let result = ImportBatch::new(report.clone())
        .commit(fresh.clone())
        .unwrap();
    assert_eq!(result.added, 4);
    assert_eq!(sorted(fresh.items()), sorted(vault.items()));
    let pk = &fresh.find_passkeys("webauthn.io".into(), vec![])[0].passkey;
    passkey_assert(pk.clone(), vec![9; 32], true).unwrap();
    let again = ImportBatch::new(report).preview(fresh.clone());
    assert_eq!((again.to_add, again.duplicates), (0, 4));
}

#[test]
fn encrypted_export_round_trips() {
    let vault = full_vault();
    let sealed = export_encrypted_json(vault.clone(), "export pw".into()).unwrap();
    assert!(export_is_encrypted(sealed.clone()));
    assert!(!export_is_encrypted(
        export_json(vault.clone()).into_bytes()
    ));
    let text = String::from_utf8(sealed.clone()).unwrap();
    // Whole values: a short one ("kim") turns up in a few KB of base64 by chance now and then.
    assert!(!text.contains("\"kim\"") && !text.contains("4111111111111111"));
    let file: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
    assert_eq!(file["format"], "passyble-export-encrypted");
    assert_eq!(file["kdf"]["alg"], "argon2id");
    assert_eq!(file["kdf"]["m_kib"], 65536);

    let err = import_parse(sealed.clone(), "export.json".into(), None).unwrap_err();
    assert!(err.to_string().contains("encrypted"), "{err}");
    assert!(matches!(
        import_parse_with_password(sealed.clone(), "export.json".into(), "nope".into()),
        Err(PassError::InvalidPassword)
    ));
    let batch =
        import_parse_with_password(sealed.clone(), "export.json".into(), "export pw".into())
            .unwrap();
    assert_eq!(batch.item_count(), 4);
    let fresh = new_vault("other");
    batch.commit(fresh.clone()).unwrap();
    assert_eq!(sorted(fresh.items()), sorted(vault.items()));
    let plain = export_decrypt(sealed, "export pw".into()).unwrap();
    assert!(String::from_utf8(plain)
        .unwrap()
        .contains("passyble-export"));
    let csv = b"name,url,username,password\nsite,https://site.test,u,p\n".to_vec();
    assert_eq!(
        import_parse_with_password(csv, "x.csv".into(), "".into())
            .unwrap()
            .item_count(),
        1
    );
}

#[test]
fn bitwarden_csv_export_round_trips_logins() {
    let vault = full_vault();
    let csv = export_csv(vault.clone());
    let header = csv.lines().next().unwrap();
    assert_eq!(
        header,
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp"
    );
    assert!(!csv.contains("Trashed"));
    let report = parse_import(csv.as_bytes(), "bitwarden.csv", None).unwrap();
    assert_eq!(report.format, ImportFormat::BitwardenCsv);
    assert_eq!(report.items.len(), 4);
    let original = vault
        .items()
        .into_iter()
        .find(|i| i.title == "WebAuthn")
        .unwrap();
    let back = report.items.iter().find(|i| i.title == "WebAuthn").unwrap();
    assert_eq!(back.kind, ItemKind::Login);
    assert_eq!(back.username, original.username);
    assert_eq!(back.password, original.password);
    assert_eq!(back.totp, original.totp);
    assert_eq!(back.notes, original.notes);
    assert!(back.favorite);
    assert_eq!(back.tags, ["Work"], "one folder");
    assert_eq!(
        back.urls,
        ["https://webauthn.io", "androidapp://io.webauthn"],
        "Android apps as Bitwarden URIs"
    );
    let fields: Vec<(&str, &str)> = back
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.value.as_str()))
        .collect();
    assert_eq!(
        fields,
        [("Security question", "pet"), ("Backup", "1111-2222")]
    );
    // Cards and identities come back as notes carrying their details.
    let card = report
        .items
        .iter()
        .find(|i| i.title.starts_with("Visa"))
        .unwrap();
    assert_eq!(card.kind, ItemKind::Note);
    assert!(card
        .fields
        .iter()
        .any(|f| f.name == "Number" && f.value == "4111111111111111"));
    assert!(card
        .fields
        .iter()
        .any(|f| f.name == "Expiry" && f.value == "07/2031"));
}

#[test]
fn password_health_report() {
    let vault = new_vault("d");
    let now = 1_800_000_000_000i64;
    let year = 365 * 24 * 60 * 60 * 1000i64;
    let weak = vault
        .upsert(login("Weak", "https://weak.example", "w", "123456"))
        .unwrap();
    let r1 = vault
        .upsert(login(
            "Reused 1",
            "https://r1.example",
            "r",
            "Xk9#mQ2!vLp7@wZ4",
        ))
        .unwrap();
    let r2 = vault
        .upsert(login(
            "Reused 2",
            "https://r2.example",
            "r",
            "Xk9#mQ2!vLp7@wZ4",
        ))
        .unwrap();
    let old = vault
        .upsert(Item {
            password_changed_at: now - year - 1000,
            ..login("Old", "https://old.example", "o", "Gq7$Lm2#Rt9!Vw4%")
        })
        .unwrap();
    let fine = vault
        .upsert(Item {
            password_changed_at: now - 1000,
            ..login(
                "Fine",
                "https://www.fine.example",
                "f",
                "bodefa-kitusa-mepiro-gavuno",
            )
        })
        .unwrap();
    let trashed = vault
        .upsert(login("Trashed", "https://t.example", "t", "123456"))
        .unwrap();
    vault.delete(trashed.id).unwrap();
    vault
        .upsert(Item {
            kind: ItemKind::Note,
            title: "No password".into(),
            ..Default::default()
        })
        .unwrap();

    let mut items = vault.items();
    // Pretend the fresh items were changed just before `now`.
    for i in &mut items {
        if i.password_changed_at > now {
            i.password_changed_at = now - 1000;
        }
    }
    let report = health_report(&items, now);
    assert_eq!(report.checked, 5);
    assert_eq!(ids(report.weak.clone(), |h| &h.item_id), [weak.id.as_str()]);
    assert_eq!(report.weak[0].score, 0);
    assert_eq!(report.reused.len(), 1);
    assert_eq!(
        ids(report.reused[0].items.clone(), |h| &h.item_id),
        [r1.id.clone(), r2.id.clone()]
    );
    assert_eq!(report.reused[0].items[0].reuse_count, 2);
    assert_eq!(ids(report.old.clone(), |h| &h.item_id), [old.id.as_str()]);
    assert_eq!(report.healthy, 1);
    assert!(report
        .weak
        .iter()
        .chain(&report.old)
        .all(|h| h.item_id != fine.id));
    assert_eq!(report.old[0].domain, "old.example");
    assert!(!format!("{report:?}").contains("123456"));

    // Through the vault, at the current time: the trash is left out.
    let live = password_health(vault.clone());
    assert_eq!(live.checked, 5);
    assert_eq!(live.weak.len(), 1);
    assert!(password_strength("".into()).score == 0);
    assert!(password_strength("correct-horse-battery-staple-orbit".into()).score >= 3);
}

#[test]
fn health_use_https_changes_only_what_is_safe() {
    let vault = new_vault("d");
    let saved = vault
        .upsert(Item {
            urls: vec![
                "http://example.com/login".into(),
                "http://example.com:8080".into(),
                "http://192.168.1.1".into(),
                "https://example.com".into(),
            ],
            ..login("Mixed", "", "u", "Xk9#mQ2!vLp7@wZ4")
        })
        .unwrap();
    let report = password_health(vault.clone());
    assert_eq!(report.insecure.len(), 1);
    assert_eq!(
        report.insecure[0].urls,
        ["http://example.com/login", "http://example.com:8080"]
    );
    assert!(!report.insecure[0].can_use_https, "one has a port");
    assert_eq!(
        health_use_https(vault.clone(), saved.id.clone()).unwrap(),
        1
    );
    let after = vault.get(saved.id.clone()).unwrap();
    assert_eq!(
        after.urls,
        [
            "https://example.com/login",
            "http://example.com:8080",
            "http://192.168.1.1",
            "https://example.com"
        ]
    );
    assert_eq!(after.password, "Xk9#mQ2!vLp7@wZ4");
    assert_eq!(after.password_changed_at, saved.password_changed_at);
    assert_eq!(health_use_https(vault.clone(), saved.id).unwrap(), 0);
    assert!(matches!(
        health_use_https(vault, "missing".into()),
        Err(PassError::NotFound(_))
    ));

    let github = site_security("https://github.com".into()).unwrap();
    assert!(github.two_factor.iter().any(|m| m == "totp"));
    assert!(site_security("https://intranet.invalid".into()).is_none());
}
