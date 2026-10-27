mod store;

use std::time::Instant;
use store::{HubStore, JsonStore, RedbStore};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let count = arguments
        .next()
        .map(|raw| raw.parse::<u32>())
        .transpose()?
        .unwrap_or(50);
    if arguments.next().is_some() || !(1..=500).contains(&count) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected optional record count between 1 and 500",
        )
        .into());
    }
    let json_dir = tempfile::tempdir()?;
    let redb_dir = tempfile::tempdir()?;
    let json = JsonStore::open(json_dir.path())?;
    let redb = RedbStore::open(redb_dir.path().join("hub.redb"))?;
    println!("Hub persistence A/B PoC; ephemeral data only; {count} host writes and readbacks");
    measure("json-v2", &json, count)?;
    measure("redb-4.4.0", &redb, count)?;
    println!(
        "Comparison is local-process wall time; not a production workload or adoption decision."
    );
    Ok(())
}

fn measure(
    label: &str,
    store: &impl HubStore,
    count: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    for index in 0..count {
        let id = format!("machine-{index:04}");
        store.register_host(&id, &format!("host-{index:04}"), 20_000 + index as u16)?;
        let invite = format!("{index:064x}");
        store.create_invite(&invite, i64::MAX)?;
        store.redeem_invite(&invite, &id, 1)?;
    }
    let write_elapsed = start.elapsed();
    let read_start = Instant::now();
    let snapshot = store.snapshot()?;
    let read_elapsed = read_start.elapsed();
    println!(
        "{label}: {count} host+invite transactions={write_elapsed:?}, snapshot({} hosts, {} invites)={read_elapsed:?}",
        snapshot.hosts.len(),
        snapshot.invites.len()
    );
    Ok(())
}
