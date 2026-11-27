//! Merge safety: deletions racing edits, and the merge's algebra (commutative, idempotent,
//! converging) checked over many random histories of three devices.
//!
//! Every device is a copy of one vault opened with its own device id. "Sync" is `merge_remote` with
//! the other copy's file, which is what every transport ends up calling.

use pass_core::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

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

/// A copy of `vault` as another device opens it.
fn copy_as(vault: &Vault, device: &str) -> Arc<Vault> {
    Vault::unlock_with_key(
        vault.serialize().unwrap(),
        vault.export_vault_key(),
        device.into(),
    )
    .unwrap()
}

fn login(title: &str, password: &str) -> Item {
    Item {
        title: title.into(),
        username: "kim".into(),
        password: password.into(),
        urls: vec![format!("https://{}.example", title.to_lowercase())],
        ..Default::default()
    }
}

/// Lets the millisecond clock move on, so two steps get different timestamps.
fn tick() {
    std::thread::sleep(Duration::from_millis(3));
}

/// Both ways, as two devices syncing through a server would.
fn sync(a: &Vault, b: &Vault) {
    b.merge_remote(a.serialize().unwrap()).unwrap();
    a.merge_remote(b.serialize().unwrap()).unwrap();
}

/// Everything a user can see: live items and the trash, by id.
fn contents(v: &Vault) -> (Vec<Item>, Vec<Item>) {
    let mut live = v.items();
    live.sort_by(|a, b| a.id.cmp(&b.id));
    let mut trash = v.trashed_items();
    trash.sort_by(|a, b| a.id.cmp(&b.id));
    (live, trash)
}

/// What a user sees of an item, without its version metadata (`updated_at`): two devices that
/// merged the same copies in a different order may each have made the version that keeps a
/// rescued password (see `a_concurrent_password_change_is_kept_in_the_history`), with the same
/// contents.
type View = (
    String,
    String,
    String,
    String,
    bool,
    bool,
    Vec<(String, i64)>,
);

fn view(v: &Vault) -> Vec<View> {
    let (live, trash) = contents(v);
    let mut out: Vec<View> = live
        .iter()
        .chain(trash.iter())
        .map(|i| {
            (
                i.id.clone(),
                i.title.clone(),
                i.password.clone(),
                i.notes.clone(),
                i.favorite,
                i.trashed_at.is_some(),
                i.password_history
                    .iter()
                    .map(|h| (h.password.clone(), h.replaced_at))
                    .collect(),
            )
        })
        .collect();
    out.sort();
    out
}

/// Syncs every pair of `devices` until nothing changes any more (at most a few rounds).
fn sync_all(devices: &[Arc<Vault>]) {
    for _ in 0..6 {
        let before: Vec<_> = devices.iter().map(|v| contents(v)).collect();
        for i in 0..devices.len() {
            for j in 0..devices.len() {
                if i != j {
                    devices[j]
                        .merge_remote(devices[i].serialize().unwrap())
                        .unwrap();
                }
            }
        }
        let after: Vec<_> = devices.iter().map(|v| contents(v)).collect();
        if before == after && after.windows(2).all(|w| w[0] == w[1]) {
            return;
        }
    }
    panic!("the devices did not settle");
}

/// A laptop trashes an item and is then closed for a month. Meanwhile the phone restores the
/// item and keeps using it (a new password). When the laptop is opened again, its unlock purges
/// what it had in its trash for 30 days before it syncs. That purge must not delete the item the
/// phone brought back: the phone's restore is newer than the trashing the purge acts on.
#[test]
fn a_restore_elsewhere_survives_the_automatic_purge() {
    let laptop = new_vault("laptop");
    let item = laptop.upsert(login("Bank", "one")).unwrap();
    let phone = copy_as(&laptop, "phone");

    laptop.delete(item.id.clone()).unwrap();
    phone.merge_remote(laptop.serialize().unwrap()).unwrap();
    assert!(phone.get(item.id.clone()).is_none(), "in the phone's trash");

    tick();
    phone.restore(item.id.clone()).unwrap();
    tick();
    let mut changed = phone.get(item.id.clone()).unwrap();
    changed.password = "two".into();
    phone.upsert(changed).unwrap();

    tick();
    let month = 31 * 24 * 60 * 60 * 1000;
    let now = phone.get(item.id.clone()).unwrap().updated_at + month;
    assert_eq!(laptop.purge_expired_trash(now), 1);
    assert!(laptop.trashed_items().is_empty());

    sync(&laptop, &phone);
    for v in [&laptop, &phone] {
        let kept = v.get(item.id.clone()).expect("the phone's restore wins");
        assert_eq!(kept.password, "two");
        assert!(kept.trashed_at.is_none());
    }
    assert_eq!(contents(&laptop), contents(&phone));
}

/// "Delete for good" on one device and an edit of the same item on another, neither having seen
/// the other: the edit is kept (the item comes back with it) instead of being deleted unseen.
/// A copy that is merely old (it lacks the edit) still can't bring the deleted item back.
#[test]
fn an_edit_elsewhere_survives_a_permanent_delete_but_a_stale_copy_does_not() {
    let laptop = new_vault("laptop");
    let item = laptop.upsert(login("Mail", "one")).unwrap();
    let other = laptop.upsert(login("Shop", "one")).unwrap();
    let stale = laptop.serialize().unwrap();
    let phone = copy_as(&laptop, "phone");

    tick();
    let mut edited = phone.get(item.id.clone()).unwrap();
    edited.password = "new".into();
    phone.upsert(edited).unwrap();
    tick();
    laptop.delete_permanently(item.id.clone()).unwrap();
    laptop.delete_permanently(other.id.clone()).unwrap();

    sync(&laptop, &phone);
    for v in [&laptop, &phone] {
        assert_eq!(v.get(item.id.clone()).expect("edit kept").password, "new");
        assert!(
            v.get(other.id.clone()).is_none(),
            "untouched item stays deleted"
        );
    }
    assert_eq!(contents(&laptop), contents(&phone));

    // The copy from before the deletion brings nothing back.
    let stats = laptop.merge_remote(stale).unwrap();
    assert_eq!(stats.added + stats.updated + stats.deleted, 0);
    assert!(laptop.get(other.id.clone()).is_none());
}

/// Emptying the trash on one device while another restores one of its items: the restored item
/// stays; the rest of the trash is deleted everywhere.
#[test]
fn a_restore_elsewhere_survives_empty_trash() {
    let laptop = new_vault("laptop");
    let a = laptop.upsert(login("A", "a")).unwrap();
    let b = laptop.upsert(login("B", "b")).unwrap();
    laptop.delete(a.id.clone()).unwrap();
    laptop.delete(b.id.clone()).unwrap();
    let phone = copy_as(&laptop, "phone");

    tick();
    phone.restore(a.id.clone()).unwrap();
    tick();
    assert_eq!(laptop.empty_trash(), 2);

    sync(&laptop, &phone);
    for v in [&laptop, &phone] {
        assert!(v.get(a.id.clone()).is_some(), "restored item kept");
        assert!(v.get(b.id.clone()).is_none());
        assert!(v.trashed_items().is_empty());
    }
}

/// The live items titled `title`, for finding conflict copies.
fn titled(v: &Vault, title: &str) -> Vec<Item> {
    v.items().into_iter().filter(|i| i.title == title).collect()
}

/// Asserts that one more exchange in each direction changes nothing.
fn assert_settled(a: &Vault, b: &Vault) {
    let stats = a.merge_remote(b.serialize().unwrap()).unwrap();
    assert_eq!(stats.added + stats.updated + stats.deleted, 0, "settled");
    let stats = b.merge_remote(a.serialize().unwrap()).unwrap();
    assert_eq!(stats.added + stats.updated + stats.deleted, 0, "settled");
    assert_eq!(contents(a), contents(b));
}

/// The phone edits a login's notes while the PC, not synced, edits its username. Both edits are
/// kept on both devices, whichever device merges first, with no conflict copy: they changed
/// different fields.
#[test]
fn phone_edits_notes_pc_edits_username_both_edits_are_kept() {
    for phone_merges_first in [true, false] {
        let pc = new_vault("pc");
        let item = pc.upsert(login("Site", "one")).unwrap();
        let phone = copy_as(&pc, "phone");

        let mut on_phone = item.clone();
        on_phone.notes = "phone note".into();
        phone.upsert(on_phone).unwrap();
        tick();
        let mut on_pc = item.clone();
        on_pc.username = "kim.pc".into();
        pc.upsert(on_pc).unwrap();

        if phone_merges_first {
            phone.merge_remote(pc.serialize().unwrap()).unwrap();
        } else {
            pc.merge_remote(phone.serialize().unwrap()).unwrap();
        }
        let both = [pc.clone(), phone.clone()];
        sync_all(&both);
        for v in &both {
            let kept = v.get(item.id.clone()).unwrap();
            assert_eq!(kept.notes, "phone note", "the phone's edit is kept");
            assert_eq!(kept.username, "kim.pc", "the PC's edit is kept");
            assert_eq!(kept.password, "one");
            assert_eq!(v.items().len(), 1, "no conflict copy for different fields");
        }
        assert_settled(&pc, &phone);
    }
}

/// Both devices change the same field (the notes) to different values without syncing in
/// between. The newer value is kept on the item, and the other device's version of the item is
/// kept as a conflict copy ("Site (conflict)", made the same on every device) for the user to
/// merge or delete. Resolving it (deleting the copy) syncs, and old copies of the vault merged
/// later don't bring it back.
#[test]
fn the_same_field_edited_on_two_devices_keeps_the_newer_value_and_a_conflict_copy() {
    for phone_merges_first in [true, false] {
        let pc = new_vault("pc");
        let item = pc.upsert(login("Site", "one")).unwrap();
        let phone = copy_as(&pc, "phone");

        let mut on_pc = item.clone();
        on_pc.notes = "pc note".into();
        on_pc.username = "kim.pc".into();
        pc.upsert(on_pc).unwrap();
        let pc_before = pc.serialize().unwrap();
        tick();
        let mut on_phone = item.clone();
        on_phone.notes = "phone note".into();
        phone.upsert(on_phone).unwrap();
        let phone_before = phone.serialize().unwrap();

        if phone_merges_first {
            phone.merge_remote(pc.serialize().unwrap()).unwrap();
        } else {
            pc.merge_remote(phone.serialize().unwrap()).unwrap();
        }
        let both = [pc.clone(), phone.clone()];
        sync_all(&both);
        for v in &both {
            let kept = v.get(item.id.clone()).unwrap();
            assert_eq!(kept.notes, "phone note", "the newer value wins");
            assert_eq!(kept.username, "kim.pc", "the PC's other edit is merged in");
            let copies = titled(v, "Site (conflict)");
            assert_eq!(copies.len(), 1, "one conflict copy");
            assert_eq!(
                copies[0].notes, "pc note",
                "the older value is kept in the copy"
            );
            assert_eq!(copies[0].username, "kim.pc");
            assert_eq!(copies[0].password, "one");
            assert_eq!(copies[0].urls, item.urls);
            assert_ne!(copies[0].id, item.id);
        }
        assert_settled(&pc, &phone);

        let copy = titled(&phone, "Site (conflict)").remove(0);
        phone.delete_permanently(copy.id.clone()).unwrap();
        sync(&pc, &phone);
        for v in [&pc, &phone] {
            v.merge_remote(pc_before.clone()).unwrap();
            v.merge_remote(phone_before.clone()).unwrap();
            assert!(titled(v, "Site (conflict)").is_empty(), "resolved for good");
            assert_eq!(v.get(item.id.clone()).unwrap().notes, "phone note");
        }
        assert_settled(&pc, &phone);
    }
}

/// The user changes a password on the phone (the site now expects it) while the laptop, not
/// synced, edits the same login's notes a moment later. Both edits are kept, and the password
/// the phone replaced is in the history as after any change.
#[test]
fn a_concurrent_password_change_and_note_edit_are_both_kept() {
    for phone_merges_first in [true, false] {
        let laptop = new_vault("laptop");
        let item = laptop.upsert(login("Bank", "old")).unwrap();
        let phone = copy_as(&laptop, "phone");

        let mut on_phone = item.clone();
        on_phone.password = "new-on-phone".into();
        phone.upsert(on_phone).unwrap();
        tick();
        let mut on_laptop = item.clone();
        on_laptop.notes = "laptop note".into();
        laptop.upsert(on_laptop).unwrap();

        if phone_merges_first {
            phone.merge_remote(laptop.serialize().unwrap()).unwrap();
        } else {
            laptop.merge_remote(phone.serialize().unwrap()).unwrap();
        }
        let both = [laptop.clone(), phone.clone()];
        sync_all(&both);
        for v in &both {
            let kept = v.get(item.id.clone()).unwrap();
            assert_eq!(kept.notes, "laptop note");
            assert_eq!(
                kept.password, "new-on-phone",
                "the phone's password is not lost"
            );
            let history: Vec<&str> = kept
                .password_history
                .iter()
                .map(|h| h.password.as_str())
                .collect();
            assert_eq!(history, ["old"]);
            assert_eq!(v.items().len(), 1);
        }
        assert_settled(&laptop, &phone);
    }
}

/// Both devices change the password. The newer one is kept, and the other one goes into the
/// password history (not a conflict copy: the history is where replaced passwords live).
#[test]
fn both_devices_change_the_password_the_other_one_is_kept_in_the_history() {
    for phone_merges_first in [true, false] {
        let laptop = new_vault("laptop");
        let item = laptop.upsert(login("Bank", "old")).unwrap();
        let phone = copy_as(&laptop, "phone");

        let mut on_laptop = item.clone();
        on_laptop.password = "laptop-new".into();
        laptop.upsert(on_laptop).unwrap();
        tick();
        let mut on_phone = item.clone();
        on_phone.password = "phone-new".into();
        phone.upsert(on_phone).unwrap();

        if phone_merges_first {
            phone.merge_remote(laptop.serialize().unwrap()).unwrap();
        } else {
            laptop.merge_remote(phone.serialize().unwrap()).unwrap();
        }
        let both = [laptop.clone(), phone.clone()];
        sync_all(&both);
        for v in &both {
            let kept = v.get(item.id.clone()).unwrap();
            assert_eq!(kept.password, "phone-new", "the newer password wins");
            let history: Vec<&str> = kept
                .password_history
                .iter()
                .map(|h| h.password.as_str())
                .collect();
            assert!(history.contains(&"laptop-new"), "{history:?}");
            assert!(history.contains(&"old"), "{history:?}");
            assert_eq!(v.items().len(), 1, "no conflict copy for a password");
        }
        assert_settled(&laptop, &phone);
    }
}

/// Two processes of one device (an app and its AutoFill extension) share a device id, so the
/// version vector takes the later one's write as made on top of the earlier one even when it was
/// made on a stale copy. A password one of them saved is still not lost: password histories are
/// always joined, so it is kept in the history of the other's password.
#[test]
fn two_processes_of_one_device_changing_the_password_keep_both() {
    let base = new_vault("laptop");
    let item = base.upsert(login("Bank", "old")).unwrap();
    let app = copy_as(&base, "phone");
    let extension = copy_as(&base, "phone");

    let mut saved = item.clone();
    saved.password = "from-extension".into();
    extension.upsert(saved).unwrap();
    tick();
    let mut stale = item.clone();
    stale.password = "from-app".into();
    app.upsert(stale).unwrap();

    app.merge_remote(extension.serialize().unwrap()).unwrap();
    let kept = app.get(item.id.clone()).unwrap();
    assert_eq!(kept.password, "from-app");
    let history: Vec<&str> = kept
        .password_history
        .iter()
        .map(|h| h.password.as_str())
        .collect();
    assert!(history.contains(&"from-extension"), "{history:?}");
    sync_all(&[app.clone(), extension.clone(), base.clone()]);
    assert_settled(&app, &extension);
}

/// Lists (websites, tags, custom fields) that both devices changed are joined: nothing either
/// device added is dropped, and no conflict copy is needed.
#[test]
fn lists_changed_on_two_devices_keep_what_both_added() {
    let laptop = new_vault("laptop");
    let item = laptop.upsert(login("Shop", "one")).unwrap();
    let phone = copy_as(&laptop, "phone");

    let mut on_laptop = item.clone();
    on_laptop.urls.push("https://laptop.example".into());
    on_laptop.tags = vec!["Work".into()];
    laptop.upsert(on_laptop).unwrap();
    tick();
    let mut on_phone = item.clone();
    on_phone.urls.push("https://phone.example".into());
    on_phone.tags = vec!["Home".into()];
    phone.upsert(on_phone).unwrap();

    sync_all(&[laptop.clone(), phone.clone()]);
    for v in [&laptop, &phone] {
        let kept = v.get(item.id.clone()).unwrap();
        for url in [
            "https://shop.example",
            "https://laptop.example",
            "https://phone.example",
        ] {
            assert!(
                kept.urls.iter().any(|u| u == url),
                "{url} in {:?}",
                kept.urls
            );
        }
        assert_eq!(kept.tags.len(), 2, "{:?}", kept.tags);
        assert_eq!(v.items().len(), 1);
    }
    assert_settled(&laptop, &phone);
}

/// One device turns a card into a secure note (which drops the card's data) while another,
/// not synced, changes the card's number. The new number is not dropped: the phone's version
/// stays a card, as a conflict copy, on every device.
#[test]
fn a_kind_change_racing_a_card_edit_keeps_the_card() {
    for phone_merges_first in [true, false] {
        let laptop = new_vault("laptop");
        let card = laptop
            .upsert(Item {
                kind: ItemKind::Card,
                title: "Visa".into(),
                card: Some(CardData {
                    number: "4111111111111111".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap();
        let phone = copy_as(&laptop, "phone");

        laptop
            .upsert(Item {
                kind: ItemKind::Note,
                notes: "now a note".into(),
                ..card.clone()
            })
            .unwrap();
        tick();
        let mut on_phone = card.clone();
        on_phone.card.as_mut().unwrap().number = "4000056655665556".into();
        phone.upsert(on_phone).unwrap();

        if phone_merges_first {
            phone.merge_remote(laptop.serialize().unwrap()).unwrap();
        } else {
            laptop.merge_remote(phone.serialize().unwrap()).unwrap();
        }
        let both = [laptop.clone(), phone.clone()];
        sync_all(&both);
        for v in &both {
            let cards: Vec<Item> = v
                .items()
                .into_iter()
                .filter(|i| {
                    i.kind == ItemKind::Card
                        && i.card
                            .as_ref()
                            .is_some_and(|c| c.number == "4000056655665556")
                })
                .collect();
            assert!(!cards.is_empty(), "the new number is kept: {:?}", v.items());
            assert!(v.items().iter().any(|i| i.notes == "now a note"));
        }
        assert_settled(&laptop, &phone);
    }
}

/// Three devices each change a different field of one item before any of them syncs, and then
/// sync in pairs in different orders: all three edits end up on every device.
#[test]
fn three_devices_editing_different_fields_all_keep_their_edits() {
    let orders: [[(usize, usize); 4]; 3] = [
        [(0, 1), (1, 2), (2, 0), (0, 1)],
        [(2, 1), (0, 2), (1, 0), (2, 1)],
        [(1, 0), (2, 0), (0, 1), (0, 2)],
    ];
    for order in orders {
        let base = new_vault("base");
        let item = base.upsert(login("Site", "one")).unwrap();
        let devices: Vec<Arc<Vault>> = ["a", "b", "c"].iter().map(|d| copy_as(&base, d)).collect();
        let edits: [fn(&mut Item); 3] = [
            |i| i.notes = "from a".into(),
            |i| i.username = "from-b".into(),
            |i| i.title = "From C".into(),
        ];
        for (v, edit) in devices.iter().zip(edits) {
            let mut changed = item.clone();
            edit(&mut changed);
            v.upsert(changed).unwrap();
            tick();
        }
        for (from, into) in order {
            devices[into]
                .merge_remote(devices[from].serialize().unwrap())
                .unwrap();
        }
        sync_all(&devices);
        for v in &devices {
            let kept = v.get(item.id.clone()).unwrap();
            assert_eq!(
                (
                    kept.notes.as_str(),
                    kept.username.as_str(),
                    kept.title.as_str()
                ),
                ("from a", "from-b", "From C")
            );
            assert_eq!(v.items().len(), 1);
        }
    }
}

/// An ordinary edit on top of a synced version is no conflict: nothing is added to the history
/// beyond the edit's own entry, and an old copy merged later (a conflict copy, a backup, an old
/// Drive revision) adds nothing either.
#[test]
fn ordinary_edits_and_old_copies_add_nothing_to_the_history() {
    let laptop = new_vault("laptop");
    let item = laptop.upsert(login("Mail", "one")).unwrap();
    let old_copy = laptop.serialize().unwrap();
    let phone = copy_as(&laptop, "phone");
    tick();
    let mut changed = phone.get(item.id.clone()).unwrap();
    changed.password = "two".into();
    phone.upsert(changed).unwrap();
    tick();
    let mut changed = phone.get(item.id.clone()).unwrap();
    changed.notes = "n".into();
    phone.upsert(changed).unwrap();

    sync(&laptop, &phone);
    laptop.merge_remote(old_copy.clone()).unwrap();
    phone.merge_remote(old_copy).unwrap();
    for v in [&laptop, &phone] {
        let kept = v.get(item.id.clone()).unwrap();
        assert_eq!(kept.password, "two");
        let history: Vec<&str> = kept
            .password_history
            .iter()
            .map(|h| h.password.as_str())
            .collect();
        assert_eq!(history, ["one"], "only the edit's own entry");
    }
    assert_eq!(contents(&laptop), contents(&phone));
}

/// A save that fails must not mark the change saved: `save_snapshot` leaves the vault dirty
/// until `mark_saved`, and a change made after the snapshot keeps it dirty.
#[test]
fn a_snapshot_is_saved_only_when_marked() {
    let vault = new_vault("laptop");
    vault.serialize().unwrap();
    assert!(!vault.is_dirty());
    vault.upsert(login("A", "a")).unwrap();
    let first = vault.save_snapshot().unwrap();
    assert!(vault.is_dirty(), "the write may still fail");
    // The write failed: nothing is marked; the next snapshot has the change too.
    let second = vault.save_snapshot().unwrap();
    assert_eq!(first.generation, second.generation);
    vault.upsert(login("B", "b")).unwrap();
    vault.mark_saved(second.generation);
    assert!(
        vault.is_dirty(),
        "B came after the snapshot that was written"
    );
    let third = vault.save_snapshot().unwrap();
    vault.mark_saved(third.generation);
    assert!(!vault.is_dirty());
    let reopened =
        Vault::unlock_with_key(third.bytes, vault.export_vault_key(), "x".into()).unwrap();
    assert_eq!(reopened.items().len(), 2);
}

/// A small deterministic random generator (xorshift64*), so the property test needs no crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// A field the property test edits with a value no other edit uses, so it can tell afterwards
/// whether the edit is still somewhere in the vault.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Part {
    Title,
    Username,
    Password,
    Notes,
    Url,
}

/// One edit of the property test: item `item`'s `part` set to `value` by a write at `at`, by a
/// device that knew the edits in `known` (its own and those its merges brought it). `created_at`
/// is the item's, which its conflict copies keep: an edit of a copy can replace a value that only
/// the copy still had.
struct Edit {
    item: String,
    created_at: i64,
    part: Part,
    value: String,
    at: i64,
    known: BTreeSet<usize>,
}

/// A "delete for good" or purge: the tombstone's version and what the deleting device knew.
struct Deletion {
    item: String,
    created_at: i64,
    at: i64,
    known: BTreeSet<usize>,
}

/// What every device did and knew, to check that no edit is lost.
struct History {
    known: Vec<BTreeSet<usize>>,
    edits: Vec<Edit>,
    deletions: Vec<Deletion>,
}

impl History {
    fn new(devices: usize) -> History {
        History {
            known: vec![BTreeSet::new(); devices],
            edits: Vec::new(),
            deletions: Vec::new(),
        }
    }

    fn edit(&mut self, device: usize, saved: &Item, part: Part, value: String) {
        let id = self.edits.len();
        self.known[device].insert(id);
        self.edits.push(Edit {
            item: saved.id.clone(),
            created_at: saved.created_at,
            part,
            value,
            at: saved.updated_at,
            known: self.known[device].clone(),
        });
    }

    /// `device` wrote a tombstone for `item` (the version it had).
    fn deleted(&mut self, device: usize, item: &Item) {
        self.deletions.push(Deletion {
            item: item.id.clone(),
            created_at: item.created_at,
            at: item.updated_at + 1,
            known: self.known[device].clone(),
        });
    }

    fn merged(&mut self, into: usize, from: usize) {
        let theirs = self.known[from].clone();
        self.known[into].extend(theirs);
    }

    /// No edit is lost: every edit is still in the vault (on its item, in a conflict copy, in a
    /// password history, in a joined list) unless a later edit of the same field made with it in
    /// view replaced it, or a deletion took the item (one made with the edit in view, or newer
    /// than it: a deletion wins over an older concurrent edit by design).
    fn assert_nothing_lost(&self, v: &Vault, seed: u64) {
        let (live, trash) = contents(v);
        let items: Vec<&Item> = live.iter().chain(trash.iter()).collect();
        let base_title = |title: &str| -> String {
            let mut t = title;
            while let Some(rest) = t.strip_suffix(" (conflict)") {
                t = rest;
            }
            t.to_string()
        };
        for (id, e) in self.edits.iter().enumerate() {
            let replaced = self.edits.iter().enumerate().any(|(j, later)| {
                j != id
                    && (later.item == e.item || later.created_at == e.created_at)
                    && later.part == e.part
                    && later.known.contains(&id)
            });
            let deleted = self.deletions.iter().any(|d| {
                (d.item == e.item && (d.known.contains(&id) || d.at >= e.at))
                    || (d.created_at == e.created_at && d.known.contains(&id))
            });
            if replaced || deleted {
                continue;
            }
            let visible = items.iter().any(|i| match e.part {
                Part::Title => base_title(&i.title) == e.value,
                Part::Username => i.username == e.value,
                Part::Password => {
                    i.password == e.value
                        || i.password_history.iter().any(|h| h.password == e.value)
                }
                Part::Notes => i.notes == e.value,
                Part::Url => i.urls.contains(&e.value),
            });
            assert!(
                visible,
                "seed {seed}: edit {id} ({:?} of {} set to {}) is lost",
                e.part, e.item, e.value
            );
        }
    }
}

/// One random step on device `d`: add, edit (a field with a value of its own), trash, restore,
/// purge or delete an item.
fn random_step(rng: &mut Rng, v: &Vault, d: usize, n: usize, history: &mut History) {
    let live = v.items();
    let trash = v.trashed_items();
    match rng.below(7) {
        0 | 1 => {
            let saved = v.upsert(login(&format!("T{n}"), &format!("p{n}"))).unwrap();
            history.edit(d, &saved, Part::Title, format!("T{n}"));
            history.edit(d, &saved, Part::Password, format!("p{n}"));
        }
        2 | 3 if !live.is_empty() => {
            let mut item = live[rng.below(live.len())].clone();
            let edit = match rng.below(6) {
                0 => {
                    item.password = format!("p{n}");
                    Some((Part::Password, item.password.clone()))
                }
                1 => {
                    item.notes = format!("note {n}");
                    Some((Part::Notes, item.notes.clone()))
                }
                2 => {
                    item.username = format!("u{n}");
                    Some((Part::Username, item.username.clone()))
                }
                3 => {
                    item.title = format!("T{n}");
                    Some((Part::Title, item.title.clone()))
                }
                4 => {
                    let url = format!("https://u{n}.example");
                    item.urls = vec![url.clone()];
                    Some((Part::Url, url))
                }
                _ => {
                    item.favorite = !item.favorite;
                    None
                }
            };
            let saved = v.upsert(item).unwrap();
            if let Some((part, value)) = edit {
                history.edit(d, &saved, part, value);
            }
        }
        4 if !live.is_empty() => {
            v.delete(live[rng.below(live.len())].id.clone()).unwrap();
        }
        5 if !trash.is_empty() => {
            let item = &trash[rng.below(trash.len())];
            if rng.below(2) == 0 {
                v.restore(item.id.clone()).unwrap();
            } else {
                v.purge(item.id.clone()).unwrap();
                history.deleted(d, item);
            }
        }
        6 if !live.is_empty() => {
            let item = &live[rng.below(live.len())];
            v.delete_permanently(item.id.clone()).unwrap();
            history.deleted(d, item);
        }
        _ => {}
    }
}

/// Random histories of three devices (edits, trash, restores, deletes, partial syncs): merging is
/// idempotent and commutative, every sync order converges, and no edit is lost
/// ([`History::assert_nothing_lost`]) unless a device deleted or trashed the item.
#[test]
fn merge_is_commutative_idempotent_and_converges_for_random_histories() {
    for seed in 1..=60u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let base = new_vault("dev-0");
        for n in 0..3 {
            base.upsert(login(&format!("Base{n}"), "p")).unwrap();
        }
        let devices: Vec<Arc<Vault>> = (0..3)
            .map(|d| copy_as(&base, &format!("dev-{d}")))
            .collect();
        let mut history = History::new(devices.len());

        // Random edits with the occasional one-way merge in between (a partial sync).
        for n in 0..30 {
            let d = rng.below(devices.len());
            if rng.below(4) == 0 {
                let from = rng.below(devices.len());
                devices[d]
                    .merge_remote(devices[from].serialize().unwrap())
                    .unwrap();
                history.merged(d, from);
            } else {
                random_step(
                    &mut rng,
                    &devices[d],
                    d,
                    seed as usize * 100 + n,
                    &mut history,
                );
            }
            if rng.below(3) == 0 {
                // Different milliseconds, so not every step shares one timestamp.
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        // Commutative: A <- B and B <- A, on fresh copies of each.
        let (a, b) = (&devices[0], &devices[1]);
        let a1 = copy_as(a, "dev-0");
        let b1 = copy_as(b, "dev-1");
        a1.merge_remote(b.serialize().unwrap()).unwrap();
        b1.merge_remote(a.serialize().unwrap()).unwrap();
        assert_eq!(view(&a1), view(&b1), "seed {seed}: commutative");

        // Idempotent: the same copy again, and a vault with itself, change nothing.
        let before = contents(&a1);
        let again = a1.merge_remote(b.serialize().unwrap()).unwrap();
        assert_eq!(
            again.added + again.updated + again.deleted,
            0,
            "seed {seed}"
        );
        let own = a1.merge_remote(a1.serialize().unwrap()).unwrap();
        assert_eq!(own.added + own.updated + own.deleted, 0, "seed {seed}");
        assert_eq!(contents(&a1), before, "seed {seed}: idempotent");

        // Converges, whatever the order: every device ends with the same contents.
        let forward: Vec<Arc<Vault>> = devices
            .iter()
            .enumerate()
            .map(|(i, v)| copy_as(v, &format!("dev-{i}")))
            .collect();
        sync_all(&forward);
        let backward: Vec<Arc<Vault>> = devices
            .iter()
            .enumerate()
            .rev()
            .map(|(i, v)| copy_as(v, &format!("dev-{i}")))
            .collect();
        sync_all(&backward);
        let expected = contents(&forward[0]);
        for v in &forward {
            assert_eq!(contents(v), expected, "seed {seed}: converges");
        }
        let expected_backward = contents(&backward[0]);
        for v in &backward {
            assert_eq!(contents(v), expected_backward, "seed {seed}: converges");
        }

        history.assert_nothing_lost(&forward[0], seed);
        history.assert_nothing_lost(&backward[0], seed);

        // Across different orders the items, passwords, notes and trash agree, except where the
        // order itself decides: which versions lost a conflict (so which conflict copies exist),
        // the rescued history, and items a deletion raced with concurrent edits.
        let deleted: BTreeSet<&String> = history.deletions.iter().map(|d| &d.item).collect();
        let comparable = |v: &Vault| -> Vec<View> {
            view(v)
                .into_iter()
                .filter(|i| !i.1.ends_with(" (conflict)") && !deleted.contains(&i.0))
                .map(|mut i| {
                    i.6.clear();
                    i
                })
                .collect()
        };
        for v in &backward {
            assert_eq!(
                comparable(v),
                comparable(&forward[0]),
                "seed {seed}: any order"
            );
        }

        // Nothing silently vanishes. Tombstones aren't visible through the public API, so check the
        // weaker form: an id that no device deleted and every device still has stays.
        let mut everywhere: BTreeMap<String, usize> = BTreeMap::new();
        for v in &devices {
            let (live, trash) = contents(v);
            for item in live.iter().chain(trash.iter()) {
                *everywhere.entry(item.id.clone()).or_default() += 1;
            }
        }
        let (live, trash) = &expected;
        for (id, count) in everywhere {
            if count == devices.len() {
                assert!(
                    live.iter().chain(trash.iter()).any(|i| i.id == id),
                    "seed {seed}: item {id} that every device had is gone"
                );
            }
        }
    }
}
