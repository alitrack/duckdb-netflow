// DuckDB loadable extension: NetFlow / IPFIX / sFlow datagram inspection, in
// SQL — probe the export version, decode the export header, and triage
// well-formedness.
//
// Thin quack-rs binding over `netflow_core` (verbatim from Query-farm's
// vgi-netflow netflow-core crate, MIT — a pure-compute flow-export datagram
// decoder for NetFlow v5/v9, IPFIX, and sFlow v5; only `serde` / `serde_json`;
// no I/O, no network, no Arrow). Only the Arrow IPC transport was replaced with
// direct C-API vector I/O.
//
// Function surface (v1 — scalars, no file/glob source, no per-record tables):
//
//   netflow_version(payload)      -> VARCHAR  '5' / '9' / '10' / 'sflow5', NULL if unrecognized
//   netflow_header(payload)       -> STRUCT(version, count, sys_uptime, export_time,
//                                                          sequence, obs_domain)
//   netflow_well_formed(payload)  -> STRUCT(ok, version, error, kind)
//
// `payload` is a BLOB holding one flow-export datagram. All three are total:
// a non-flow / truncated blob yields NULL (version) / an all-NULL struct
// (header) / ok=false with a classified kind (well_formed) — never a SQL error.

use quack_rs::connection::{Connection, Registrar};
use quack_rs::error::ExtensionError;
use quack_rs::scalar::ScalarFunctionBuilder;
use quack_rs::types::{LogicalType, TypeId};
use quack_rs::vector::{VectorReader, VectorWriter};

use netflow_core::decode::header::{parse_header, probe_version};
use netflow_core::wellformed::well_formed;

/// Read a BLOB cell into bytes; None when the row is NULL/invalid.
unsafe fn payload_bytes(value: &VectorReader, row: usize) -> Option<Vec<u8>> {
    if !value.is_valid(row) {
        return None;
    }
    Some(value.read_blob(row).to_vec())
}

// ─────────────────────────────────────────────────────────────────────────────
// netflow_version(payload) -> VARCHAR
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(version_fn, |_info, input, output| {
    unsafe {
        let payload = VectorReader::new(input, 0);
        let row_count = payload.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            match payload_bytes(&payload, row) {
                Some(bytes) => match probe_version(&bytes) {
                    Some(v) => writer.write_varchar(row, v),
                    None => writer.set_null(row),
                },
                None => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// netflow_header(payload) -> STRUCT(version, count, sys_uptime, export_time,
//                                    sequence, obs_domain)
// version:UINTEGER is always set when the header parses; the rest are nullable.
// export_time is TIMESTAMPTZ (microseconds since the Unix epoch).
// ─────────────────────────────────────────────────────────────────────────────

const HEADER_FIELDS: &[(&str, TypeId)] = &[
    ("version", TypeId::USmallInt),
    ("count", TypeId::USmallInt),
    ("sys_uptime", TypeId::UInteger),
    ("export_time", TypeId::TimestampTz),
    ("sequence", TypeId::UBigInt),
    ("obs_domain", TypeId::UInteger),
];

quack_rs::scalar_callback!(header_fn, |_info, input, output| {
    unsafe {
        let payload = VectorReader::new(input, 0);
        let row_count = payload.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, HEADER_FIELDS.len());
        for row in 0..row_count {
            match payload_bytes(&payload, row).and_then(|b| parse_header(&b)) {
                Some(h) => {
                    sw.write_u16(row, 0, h.version);
                    match h.count {
                        Some(v) => sw.write_u16(row, 1, v),
                        None => sw.set_null(row, 1),
                    }
                    match h.sys_uptime {
                        Some(v) => sw.write_u32(row, 2, v),
                        None => sw.set_null(row, 2),
                    }
                    match h.export_time {
                        Some(v) => sw.write_timestamp(row, 3, v),
                        None => sw.set_null(row, 3),
                    }
                    match h.sequence {
                        Some(v) => sw.write_u64(row, 4, v),
                        None => sw.set_null(row, 4),
                    }
                    match h.obs_domain {
                        Some(v) => sw.write_u32(row, 5, v),
                        None => sw.set_null(row, 5),
                    }
                }
                None => {
                    sw.set_null(row, 0);
                    sw.set_null(row, 1);
                    sw.set_null(row, 2);
                    sw.set_null(row, 3);
                    sw.set_null(row, 4);
                    sw.set_null(row, 5);
                }
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// netflow_well_formed(payload) -> STRUCT(ok, version, error, kind)
// ─────────────────────────────────────────────────────────────────────────────

const WELL_FORMED_FIELDS: &[(&str, TypeId)] = &[
    ("ok", TypeId::Boolean),
    ("version", TypeId::Varchar),
    ("error", TypeId::Varchar),
    ("kind", TypeId::Varchar),
];

quack_rs::scalar_callback!(well_formed_fn, |_info, input, output| {
    unsafe {
        let payload = VectorReader::new(input, 0);
        let row_count = payload.row_count();
        let mut sw = quack_rs::vector::StructWriter::new(output, WELL_FORMED_FIELDS.len());
        for row in 0..row_count {
            match payload_bytes(&payload, row) {
                Some(bytes) => {
                    let wf = well_formed(&bytes);
                    sw.write_bool(row, 0, wf.ok);
                    match &wf.version {
                        Some(v) => sw.write_varchar(row, 1, v),
                        None => sw.set_null(row, 1),
                    }
                    match &wf.error {
                        Some(v) => sw.write_varchar(row, 2, v),
                        None => sw.set_null(row, 2),
                    }
                    match &wf.kind {
                        Some(v) => sw.write_varchar(row, 3, v),
                        None => sw.set_null(row, 3),
                    }
                }
                None => {
                    sw.set_null(row, 0);
                    sw.set_null(row, 1);
                    sw.set_null(row, 2);
                    sw.set_null(row, 3);
                }
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Registration + entry point
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    con.register_scalar(
        ScalarFunctionBuilder::new("netflow_version")
            .param(TypeId::Blob)
            .returns(TypeId::Varchar)
            .function(version_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("netflow_header")
            .param(TypeId::Blob)
            .returns_logical(LogicalType::struct_type(HEADER_FIELDS))
            .function(header_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("netflow_well_formed")
            .param(TypeId::Blob)
            .returns_logical(LogicalType::struct_type(WELL_FORMED_FIELDS))
            .function(well_formed_fn),
    )?;

    Ok(())
}

quack_rs::entry_point_v2!(netflow_init_c_api, |con| register_all(con));
