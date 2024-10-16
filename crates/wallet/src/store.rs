use std::{path::Path, str::FromStr};

use rusqlite::{params, Connection};

use crate::Scheme;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn new(password: &str, path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        let conn = unlock(password.as_bytes(), conn)?;
        Ok(Self { conn })
    }
    pub fn set_secret(&self, name: &str, scheme: Scheme, secret: &[u8]) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR ABORT INTO names (name, scheme, secret) VALUES (?, ?, ?)",
            params![name, scheme.to_string(), secret],
        )?;
        Ok(())
    }

    pub fn get_secret(&self, name: &str) -> anyhow::Result<(Vec<u8>, Scheme)> {
        let (sec, sch) = self.conn.query_row(
            "SELECT secret, scheme FROM names WHERE name = ? LIMIT 1",
            params![name],
            |row| {
                let s = row.get(0)?;
                let scheme = row.get::<_, String>(1)?;
                let scheme = Scheme::from_str(&scheme);

                Ok((s, scheme))
            },
        )?;
        Ok((sec, sch?))
    }

    pub fn delete_secret(&self, name: &str) -> anyhow::Result<()> {
        self.conn
            .execute("DELETE FROM names WHERE name = ?", params![name])?;
        Ok(())
    }

    pub fn list(&self) -> anyhow::Result<Vec<(String, Scheme)>> {
        let mut stmt = self.conn.prepare("SELECT name, scheme FROM names")?;
        let rows = stmt.query_and_then([], |row| {
            let name = row.get(0)?;
            let scheme: String = row.get(1)?;
            anyhow::Ok((name, Scheme::from_str(&scheme)?))
        })?;
        let mut names = Vec::new();
        for row in rows {
            names.push(row?);
        }
        Ok(names)
    }
}

fn unlock(key: &[u8], mut conn: Connection) -> anyhow::Result<Connection> {
    let tx = conn.transaction()?;
    tx.pragma_update(None, "key", hex::encode(key))?;
    tx.pragma_update(None, "cipher_memory_security", "ON")?;
    tx.query_row("SELECT COUNT(*) FROM `sqlite_master`;", [], |_row| Ok(()))?;
    tx.execute(
        "CREATE TABLE IF NOT EXISTS names (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            scheme TEXT NOT NULL,
            secret BLOB NOT NULL
        )",
        [],
    )?;
    tx.commit()?;
    Ok(conn)
}
