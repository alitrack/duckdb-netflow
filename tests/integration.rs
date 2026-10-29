//! SQL-level integration tests: LOAD the built `.duckdb_extension` into a real
//! in-memory DuckDB and exercise the full function surface (3 scalars).
//!
//! Run: `cargo test --release` (after the cdylib is built and stamped to
//! `target/release/netflow.duckdb_extension`).
//!
//! Bundled test DuckDB is v1.1.0: BLOBs are built with `from_hex('<hex>')`, and
//! struct-field reads via `-> 'field'` yield JSON, so numeric/bool assertions
//! CAST them (the TimestampTz field renders as a quoted string).

use quack_rs::testing::InMemoryDb;

/// A minimal NetFlow v5 datagram: 22-byte header (version=5, count=1,
/// sys_uptime=256, unix_secs=1704067200 [2024-01-01 UTC], nsecs=0,
/// sequence=7, engine_type=0, engine_id=3) + one 48-byte zeroed record.
fn v5_hex() -> &'static str {
    let mut b: Vec<u8> = Vec::new();
    let be16 = |v: u16| v.to_be_bytes().to_vec();
    let be32 = |v: u32| v.to_be_bytes().to_vec();
    b.extend(be16(5));
    b.extend(be16(1));
    b.extend(be32(256));
    b.extend(be32(1704067200));
    b.extend(be32(0));
    b.extend(be32(7));
    b.push(0); // engine_type
    b.push(3); // engine_id -> obs_domain
    b.extend_from_slice(&[0u8; 48]);
    // hex-encode (no `hex` crate in dev-deps)
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for byte in &b {
        s.push(H[(byte >> 4) as usize] as char);
        s.push(H[(byte & 0xf) as usize] as char);
    }
    Box::leak(s.into_boxed_str())
}

fn db() -> InMemoryDb {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/release/netflow.duckdb_extension");
    assert!(path.exists(), "build first: make release -> {path:?}");
    let d = InMemoryDb::open_unsigned().expect("open in-memory db");
    d.execute_batch(&format!("LOAD '{}'", path.display())).expect("load extension");
    d
}

#[test]
fn version() {
    let d = db();
    let v: String = d
        .query_one(&format!("SELECT netflow_version(from_hex('{v5}'))", v5 = v5_hex()))
        .unwrap();
    assert_eq!(v, "5");
    // Not a flow datagram -> NULL.
    let nul: Option<String> = d.query_one("SELECT netflow_version('garbage')").unwrap();
    assert!(nul.is_none());
}

#[test]
fn header() {
    let d = db();
    let hexd = v5_hex();
    let ver: i32 = d
        .query_one(&format!(
            "SELECT CAST(netflow_header(from_hex('{hexd}')) -> 'version' AS INTEGER)"
        ))
        .unwrap();
    assert_eq!(ver, 5);
    let cnt: i32 = d
        .query_one(&format!(
            "SELECT CAST(netflow_header(from_hex('{hexd}')) -> 'count' AS INTEGER)"
        ))
        .unwrap();
    assert_eq!(cnt, 1);
    let up: i32 = d
        .query_one(&format!(
            "SELECT CAST(netflow_header(from_hex('{hexd}')) -> 'sys_uptime' AS INTEGER)"
        ))
        .unwrap();
    assert_eq!(up, 256);
    let seq: i64 = d
        .query_one(&format!(
            "SELECT CAST(netflow_header(from_hex('{hexd}')) -> 'sequence' AS BIGINT)"
        ))
        .unwrap();
    assert_eq!(seq, 7);
    let obs: i32 = d
        .query_one(&format!(
            "SELECT CAST(netflow_header(from_hex('{hexd}')) -> 'obs_domain' AS INTEGER)"
        ))
        .unwrap();
    assert_eq!(obs, 3);
}

#[test]
fn well_formed() {
    let d = db();
    let hexd = v5_hex();
    // The core parses a 22-byte v5 header but validates against the 24-byte
    // on-wire header: `need = 24 + count*48 = 72`, and this datagram is
    // 22 + 48 = 70 bytes -> `short-record` (ok=false). The version still
    // probes as "5".
    let wok: i32 = d
        .query_one(&format!(
            "SELECT CAST(netflow_well_formed(from_hex('{hexd}')) -> 'ok' AS INTEGER)"
        ))
        .unwrap();
    assert_eq!(wok, 0);
    let wver: String = d
        .query_one(&format!(
            "SELECT CAST(netflow_well_formed(from_hex('{hexd}')) -> 'version' AS VARCHAR)"
        ))
        .unwrap();
    assert_eq!(wver, "\"5\"");

    // A clearly non-flow blob -> ok=false, kind 'not-a-flow-datagram'.
    let bad: i32 = d
        .query_one("SELECT CAST(netflow_well_formed(from_hex('0001')) -> 'ok' AS INTEGER)")
        .unwrap();
    assert_eq!(bad, 0);
    let kind: String = d
        .query_one("SELECT CAST(netflow_well_formed(from_hex('0001')) -> 'kind' AS VARCHAR)")
        .unwrap();
    assert_eq!(kind, "\"not-a-flow-datagram\"");
}

#[test]
fn null_input() {
    let d = db();
    let nul: Option<String> = d.query_one("SELECT netflow_version(NULL)").unwrap();
    assert!(nul.is_none());
    let nulh: Option<i32> = d
        .query_one("SELECT CAST(netflow_header(NULL) -> 'version' AS INTEGER)")
        .unwrap();
    assert!(nulh.is_none());
}
