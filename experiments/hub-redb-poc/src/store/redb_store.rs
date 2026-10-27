use super::{Host, HubStore, Invite, Snapshot, apply_host, apply_invite, apply_redeem, invalid};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::{io, path::Path};

const META: TableDefinition<&str, u32> = TableDefinition::new("meta");
const HOSTS: TableDefinition<&str, &[u8]> = TableDefinition::new("hosts");
const NAMES: TableDefinition<&str, &str> = TableDefinition::new("host_names");
const PORTS: TableDefinition<u16, &str> = TableDefinition::new("host_ports");
const INVITES: TableDefinition<&str, &[u8]> = TableDefinition::new("invites_by_digest");

/// redb implementation. redb atomicity does not replace the checks in this module.
pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let db = Database::create(path).map_err(io::Error::other)?;
        let this = Self { db };
        let read = this.db.begin_read().map_err(io::Error::other)?;
        match read.open_table(META) {
            Ok(table)
                if table
                    .get("schema-version")
                    .map_err(io::Error::other)?
                    .is_some() => {}
            Ok(_) | Err(redb::TableError::TableDoesNotExist(_)) => {
                let write = this.db.begin_write().map_err(io::Error::other)?;
                {
                    let mut meta = write.open_table(META).map_err(io::Error::other)?;
                    meta.insert("schema-version", 2).map_err(io::Error::other)?;
                    write.open_table(HOSTS).map_err(io::Error::other)?;
                    write.open_table(NAMES).map_err(io::Error::other)?;
                    write.open_table(PORTS).map_err(io::Error::other)?;
                    write.open_table(INVITES).map_err(io::Error::other)?;
                }
                write.commit().map_err(io::Error::other)?;
            }
            Err(error) => return Err(io::Error::other(error)),
        }
        let snapshot = this.snapshot()?;
        snapshot.validate()?;
        Ok(this)
    }

    fn transact(&self, update: impl FnOnce(&mut Snapshot) -> io::Result<()>) -> io::Result<()> {
        let write = self.db.begin_write().map_err(io::Error::other)?;
        let mut state = read_snapshot_write(&write)?;
        update(&mut state)?;
        state.validate()?;
        {
            let mut hosts = write.open_table(HOSTS).map_err(io::Error::other)?;
            let mut names = write.open_table(NAMES).map_err(io::Error::other)?;
            let mut ports = write.open_table(PORTS).map_err(io::Error::other)?;
            let mut invites = write.open_table(INVITES).map_err(io::Error::other)?;
            // Replace the full projection in this PoC to keep the comparison aligned with JSON.
            let host_keys = hosts
                .iter()
                .map_err(io::Error::other)?
                .map(|row| {
                    row.map(|(key, _)| key.value().to_owned())
                        .map_err(io::Error::other)
                })
                .collect::<io::Result<Vec<_>>>()?;
            for key in host_keys {
                hosts.remove(key.as_str()).map_err(io::Error::other)?;
            }
            let name_keys = names
                .iter()
                .map_err(io::Error::other)?
                .map(|row| {
                    row.map(|(key, _)| key.value().to_owned())
                        .map_err(io::Error::other)
                })
                .collect::<io::Result<Vec<_>>>()?;
            for key in name_keys {
                names.remove(key.as_str()).map_err(io::Error::other)?;
            }
            let port_keys = ports
                .iter()
                .map_err(io::Error::other)?
                .map(|row| row.map(|(key, _)| key.value()).map_err(io::Error::other))
                .collect::<io::Result<Vec<_>>>()?;
            for key in port_keys {
                ports.remove(key).map_err(io::Error::other)?;
            }
            let invite_keys = invites
                .iter()
                .map_err(io::Error::other)?
                .map(|row| {
                    row.map(|(key, _)| key.value().to_owned())
                        .map_err(io::Error::other)
                })
                .collect::<io::Result<Vec<_>>>()?;
            for key in invite_keys {
                invites.remove(key.as_str()).map_err(io::Error::other)?;
            }
            for (id, host) in &state.hosts {
                hosts
                    .insert(
                        id.as_str(),
                        serde_json::to_vec(host)
                            .map_err(io::Error::other)?
                            .as_slice(),
                    )
                    .map_err(io::Error::other)?;
                names
                    .insert(host.name.to_ascii_lowercase().as_str(), id.as_str())
                    .map_err(io::Error::other)?;
                ports
                    .insert(host.port, id.as_str())
                    .map_err(io::Error::other)?;
            }
            for (digest, invite) in &state.invites {
                invites
                    .insert(
                        digest.as_str(),
                        serde_json::to_vec(invite)
                            .map_err(io::Error::other)?
                            .as_slice(),
                    )
                    .map_err(io::Error::other)?;
            }
        }
        write.commit().map_err(io::Error::other)
    }

    #[cfg(test)]
    pub(super) fn rollback_probe(&self) -> io::Result<Snapshot> {
        {
            let write = self.db.begin_write().map_err(io::Error::other)?;
            write
                .open_table(HOSTS)
                .map_err(io::Error::other)?
                .insert("partial", br#"{"name":"partial","port":22001}"#.as_slice())
                .map_err(io::Error::other)?;
            // Deliberately drop without commit to exercise redb's transaction rollback.
        }
        self.snapshot()
    }
}

impl HubStore for RedbStore {
    fn snapshot(&self) -> io::Result<Snapshot> {
        let read = self.db.begin_read().map_err(io::Error::other)?;
        let version = read
            .open_table(META)
            .map_err(io::Error::other)?
            .get("schema-version")
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("schema version missing"))?
            .value();
        if version != 2 {
            return Err(invalid("unsupported schema version"));
        }
        let mut state = Snapshot::empty();
        for row in read
            .open_table(HOSTS)
            .map_err(io::Error::other)?
            .iter()
            .map_err(io::Error::other)?
        {
            let (id, bytes) = row.map_err(io::Error::other)?;
            state.hosts.insert(
                id.value().to_owned(),
                serde_json::from_slice::<Host>(bytes.value())
                    .map_err(|_| invalid("redb host record corrupt"))?,
            );
        }
        for row in read
            .open_table(INVITES)
            .map_err(io::Error::other)?
            .iter()
            .map_err(io::Error::other)?
        {
            let (digest, bytes) = row.map_err(io::Error::other)?;
            state.invites.insert(
                digest.value().to_owned(),
                serde_json::from_slice::<Invite>(bytes.value())
                    .map_err(|_| invalid("redb invite record corrupt"))?,
            );
        }
        state.validate()?;
        Ok(state)
    }
    fn register_host(&self, id: &str, name: &str, port: u16) -> io::Result<()> {
        self.transact(|state| apply_host(state, id, name, port))
    }
    fn create_invite(&self, digest: &str, expires_at: i64) -> io::Result<()> {
        self.transact(|state| apply_invite(state, digest, expires_at))
    }
    fn redeem_invite(&self, digest: &str, machine_id: &str, now: i64) -> io::Result<()> {
        self.transact(|state| apply_redeem(state, digest, machine_id, now))
    }
}

fn read_snapshot_write(write: &redb::WriteTransaction) -> io::Result<Snapshot> {
    let mut state = Snapshot::empty();
    for row in write
        .open_table(HOSTS)
        .map_err(io::Error::other)?
        .iter()
        .map_err(io::Error::other)?
    {
        let (id, bytes) = row.map_err(io::Error::other)?;
        state.hosts.insert(
            id.value().to_owned(),
            serde_json::from_slice::<Host>(bytes.value())
                .map_err(|_| invalid("redb host record corrupt"))?,
        );
    }
    for row in write
        .open_table(INVITES)
        .map_err(io::Error::other)?
        .iter()
        .map_err(io::Error::other)?
    {
        let (digest, bytes) = row.map_err(io::Error::other)?;
        state.invites.insert(
            digest.value().to_owned(),
            serde_json::from_slice::<Invite>(bytes.value())
                .map_err(|_| invalid("redb invite record corrupt"))?,
        );
    }
    Ok(state)
}
