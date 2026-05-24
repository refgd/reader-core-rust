use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AnalyzerSession {
    pub source_variable: String,
    pub variables: HashMap<String, String>,
    pub source_store: HashMap<String, String>,
    pub cache: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub login_info_raw: String,
    pub login_info: HashMap<String, String>,
    pub login_header: String,
    pub book_variables: HashMap<String, String>,
    pub chapter_variables: HashMap<String, String>,
    pub java_store: HashMap<String, String>,
    pub logs: Vec<String>,
    pub toasts: Vec<String>,
}

static PERSISTENT_DB_PATH: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

fn persistent_db_path() -> &'static Mutex<Option<PathBuf>> {
    PERSISTENT_DB_PATH.get_or_init(|| Mutex::new(None))
}

impl AnalyzerSession {
    pub fn get_cookie(&self, host: &str) -> String {
        trim_cookie_to_legacy_limit(
            self.cookies
                .iter()
                .find(|(domain, _)| host_matches_cookie_domain(host, domain))
                .map(|(_, value)| value.clone())
                .or_else(|| persistent_get_cookie(host).ok().flatten())
                .unwrap_or_default(),
        )
    }

    pub fn set_cookie(&mut self, host: impl Into<String>, value: impl Into<String>) {
        let host = normalize_cookie_host(&host.into());
        let value = trim_cookie_to_legacy_limit(value.into());
        self.cookies.insert(host.clone(), value.clone());
        let _ = persistent_set_cookie(&host, &value);
    }

    pub fn remove_cookie(&mut self, host: impl Into<String>) {
        let host = normalize_cookie_host(&host.into());
        self.cookies
            .retain(|domain, _| !host_matches_cookie_domain(&host, domain));
        let _ = persistent_remove_cookie(&host);
    }
}

const LEGACY_COOKIE_HEADER_LIMIT: usize = 4096;

fn trim_cookie_to_legacy_limit(cookie: String) -> String {
    if cookie.len() <= LEGACY_COOKIE_HEADER_LIMIT {
        return cookie;
    }
    let mut pairs = cookie
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            let key = key.trim();
            (!key.is_empty()).then(|| (key.to_string(), value.trim().to_string()))
        })
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    while !pairs.is_empty() {
        let joined = pairs
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if joined.len() <= LEGACY_COOKIE_HEADER_LIMIT {
            return joined;
        }
        pairs.pop();
    }
    String::new()
}

pub fn configure_persistent_store_dir(dir: impl AsRef<Path>) -> std::io::Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    let path = dir.join("analyzer.sqlite3");
    {
        let conn = open_db_at(&path).map_err(sqlite_to_io)?;
        init_db(&conn).map_err(sqlite_to_io)?;
    }
    *persistent_db_path()
        .lock()
        .expect("persistent db path poisoned") = Some(path);
    Ok(())
}

fn sqlite_to_io(err: rusqlite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}

pub fn restore_persistent_session(
    source_key: &str,
    mut session: AnalyzerSession,
) -> AnalyzerSession {
    if let Ok(Some(value)) = persistent_source_variable(source_key) {
        session.source_variable = value;
        session.variables = source_variable_map(&session.source_variable);
    } else if !session.source_variable.is_empty() {
        session.variables = source_variable_map(&session.source_variable);
        let _ = persistent_set_source_variable(source_key, &session.source_variable);
    }

    if let Ok(Some(login_info_raw)) = persistent_login_info(source_key) {
        session.login_info_raw = login_info_raw;
        session.login_info = login_info_map(&session.login_info_raw);
    } else if !session.login_info_raw.is_empty() {
        session.login_info = login_info_map(&session.login_info_raw);
        let _ = persistent_set_login_info_raw(source_key, &session.login_info_raw);
    } else if !session.login_info.is_empty() {
        let _ = persistent_set_login_info(source_key, &session.login_info);
    }

    if let Ok(Some(login_header)) = persistent_login_header(source_key) {
        session.login_header = login_header;
    } else if !session.login_header.is_empty() {
        let _ = persistent_set_login_header(source_key, &session.login_header);
    }

    for (host, cookie) in session.cookies.clone() {
        let _ = persistent_set_cookie(&host, &cookie);
    }
    session
}

pub fn persist_session(source_key: &str, session: &AnalyzerSession) {
    if !session.source_variable.is_empty() {
        let _ = persistent_set_source_variable(source_key, &session.source_variable);
    }
    if !session.login_info_raw.is_empty() {
        let _ = persistent_set_login_info_raw(source_key, &session.login_info_raw);
    } else if !session.login_info.is_empty() {
        let _ = persistent_set_login_info(source_key, &session.login_info);
    }
    if !session.login_header.is_empty() {
        let _ = persistent_set_login_header(source_key, &session.login_header);
    }
    for (key, value) in &session.source_store {
        let _ = persistent_set_source_store(source_key, key, value);
    }
    for (key, value) in &session.cache {
        let _ = persistent_set_cache(key, value);
    }
    for (host, cookie) in &session.cookies {
        let _ = persistent_set_cookie(host, cookie);
    }
}

pub fn persistent_get_cache(key: &str) -> rusqlite::Result<Option<String>> {
    get_kv("cache", "", key)
}

pub fn persistent_set_cache(key: &str, value: &str) -> rusqlite::Result<()> {
    set_kv("cache", "", key, value)
}

pub fn persistent_delete_cache(key: &str) -> rusqlite::Result<()> {
    delete_kv("cache", "", key)
}

pub fn persistent_get_source_store(
    source_key: &str,
    key: &str,
) -> rusqlite::Result<Option<String>> {
    get_kv("source_store", source_key, key)
}

pub fn persistent_set_source_store(
    source_key: &str,
    key: &str,
    value: &str,
) -> rusqlite::Result<()> {
    set_kv("source_store", source_key, key, value)
}

pub fn persistent_delete_source_store(source_key: &str, key: &str) -> rusqlite::Result<()> {
    delete_kv("source_store", source_key, key)
}

pub fn persistent_get_login_header(source_key: &str) -> rusqlite::Result<Option<String>> {
    persistent_login_header(source_key)
}

pub fn persistent_set_login_header(source_key: &str, value: &str) -> rusqlite::Result<()> {
    set_kv("login_header", source_key, "", value)
}

pub fn persistent_delete_login_header(source_key: &str) -> rusqlite::Result<()> {
    delete_kv("login_header", source_key, "")
}

pub fn persistent_get_cookie(host: &str) -> rusqlite::Result<Option<String>> {
    let host = normalize_cookie_host(host);
    if let Some(value) = get_cookie_exact(&host)? {
        return Ok(Some(value));
    }
    let conn = open_configured_db()?;
    let mut statement = conn.prepare("SELECT domain, value FROM cookies")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (domain, value) = row?;
        if host_matches_cookie_domain(&host, &domain) {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

pub fn persistent_set_cookie(host: &str, value: &str) -> rusqlite::Result<()> {
    let conn = open_configured_db()?;
    conn.execute(
        "INSERT INTO cookies(domain, value) VALUES(?1, ?2)
         ON CONFLICT(domain) DO UPDATE SET value=excluded.value",
        params![normalize_cookie_host(host), value],
    )?;
    Ok(())
}

pub fn persistent_remove_cookie(host: &str) -> rusqlite::Result<()> {
    let host = normalize_cookie_host(host);
    if host.trim().is_empty() {
        return Ok(());
    }
    let conn = open_configured_db()?;
    let mut statement = conn.prepare("SELECT domain FROM cookies")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut domains = Vec::new();
    for row in rows {
        let domain = row?;
        if host_matches_cookie_domain(&host, &domain) {
            domains.push(domain);
        }
    }
    drop(statement);
    for domain in domains {
        conn.execute("DELETE FROM cookies WHERE domain = ?1", params![domain])?;
    }
    conn.execute("DELETE FROM cookies WHERE domain = ?1", params![host])?;
    Ok(())
}

fn persistent_source_variable(source_key: &str) -> rusqlite::Result<Option<String>> {
    get_kv("source_variable", source_key, "")
}

fn persistent_set_source_variable(source_key: &str, value: &str) -> rusqlite::Result<()> {
    set_kv("source_variable", source_key, "", value)
}

fn persistent_login_info(source_key: &str) -> rusqlite::Result<Option<String>> {
    get_kv("login_info", source_key, "")
}

pub fn persistent_delete_login_info(source_key: &str) -> rusqlite::Result<()> {
    delete_kv("login_info", source_key, "")
}

fn persistent_set_login_info(
    source_key: &str,
    value: &HashMap<String, String>,
) -> rusqlite::Result<()> {
    let text = serde_json::to_string(value).unwrap_or_default();
    persistent_set_login_info_raw(source_key, &text)
}

fn persistent_set_login_info_raw(source_key: &str, text: &str) -> rusqlite::Result<()> {
    set_kv("login_info", source_key, "", text)
}

fn persistent_login_header(source_key: &str) -> rusqlite::Result<Option<String>> {
    get_kv("login_header", source_key, "")
}

fn get_kv(scope: &str, source_key: &str, key: &str) -> rusqlite::Result<Option<String>> {
    let conn = open_configured_db()?;
    conn.query_row(
        "SELECT value FROM kv WHERE scope = ?1 AND source_key = ?2 AND key = ?3",
        params![scope, source_key, key],
        |row| row.get(0),
    )
    .optional()
}

fn set_kv(scope: &str, source_key: &str, key: &str, value: &str) -> rusqlite::Result<()> {
    let conn = open_configured_db()?;
    conn.execute(
        "INSERT INTO kv(scope, source_key, key, value) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(scope, source_key, key) DO UPDATE SET value=excluded.value",
        params![scope, source_key, key, value],
    )?;
    Ok(())
}

fn delete_kv(scope: &str, source_key: &str, key: &str) -> rusqlite::Result<()> {
    let conn = open_configured_db()?;
    conn.execute(
        "DELETE FROM kv WHERE scope = ?1 AND source_key = ?2 AND key = ?3",
        params![scope, source_key, key],
    )?;
    Ok(())
}

fn get_cookie_exact(domain: &str) -> rusqlite::Result<Option<String>> {
    let conn = open_configured_db()?;
    conn.query_row(
        "SELECT value FROM cookies WHERE domain = ?1",
        params![domain],
        |row| row.get(0),
    )
    .optional()
}

fn open_configured_db() -> rusqlite::Result<Connection> {
    let path = persistent_db_path()
        .lock()
        .expect("persistent db path poisoned")
        .clone()
        .ok_or_else(|| rusqlite::Error::InvalidPath(PathBuf::from("unconfigured")))?;
    open_db_at(path)
}

fn open_db_at(path: impl AsRef<Path>) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    init_db(&conn)?;
    Ok(conn)
}

fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS kv (
            scope TEXT NOT NULL,
            source_key TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY(scope, source_key, key)
        );
        CREATE TABLE IF NOT EXISTS cookies (
            domain TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_kv_scope_source ON kv(scope, source_key);
        "#,
    )?;
    Ok(())
}

fn source_variable_map(raw: &str) -> HashMap<String, String> {
    json_object_string_map(raw)
}

fn login_info_map(raw: &str) -> HashMap<String, String> {
    json_object_string_map(raw)
}

fn json_object_string_map(raw: &str) -> HashMap<String, String> {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| {
            let value = match value {
                serde_json::Value::Null => String::new(),
                serde_json::Value::String(value) => value,
                serde_json::Value::Number(value) => value.to_string(),
                serde_json::Value::Bool(value) => value.to_string(),
                value => serde_json::to_string(&value).unwrap_or_default(),
            };
            (key, value)
        })
        .collect()
}

fn normalize_cookie_host(input: &str) -> String {
    if let Ok(url) = url::Url::parse(input) {
        if let Some(host) = url.host_str() {
            return host.to_string();
        }
    }
    input
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_matches('/')
        .to_string()
}

fn host_matches_cookie_domain(host: &str, domain: &str) -> bool {
    let host = normalize_cookie_host(host);
    let domain = normalize_cookie_host(domain);
    host.contains(domain.as_str()) || domain.contains(host.as_str())
}

#[cfg(test)]
pub fn clear_persistent_store_for_tests() {
    *persistent_db_path()
        .lock()
        .expect("persistent db path poisoned") = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_store_trims_oversized_header_to_legacy_limit() {
        let mut session = AnalyzerSession::default();
        let cookie = (0..700)
            .map(|index| format!("k{index}=value{index}"))
            .collect::<Vec<_>>()
            .join("; ");

        session.set_cookie("https://cookie.example/path", cookie);
        let trimmed = session.get_cookie("cookie.example");

        assert!(trimmed.len() <= LEGACY_COOKIE_HEADER_LIMIT);
        assert!(trimmed.contains("k0=value0"));
        assert!(!trimmed.contains("k699=value699"));
    }
}
