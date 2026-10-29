# duckdb-netflow

**NetFlow / IPFIX / sFlow datagrams, in SQL.** Probe the export version, decode
the export header, and triage well-formedness — right in DuckDB, with the
parser compiled in (pure Rust, no `pdq`, no `libnetflow`, no `suricata`).

```sql
LOAD 'netflow.duckdb_extension';

-- A NetFlow v5 datagram (header + records) as a BLOB
SELECT netflow_version(from_hex('00050001...'))  AS ver;   -- 5
SELECT netflow_header(from_hex('00050001...'))   AS h;
-- STRUCT(version=5, count=1, sys_uptime=256, export_time=TIMESTAMPTZ, sequence=7, obs_domain=3)
SELECT netflow_well_formed(from_hex('00050001...')) -> 'ok';   -- true / false
```

## Why

Flow-export captures (NetFlow v5/v9, IPFIX, sFlow) are the raw material of
network telemetry. Inspecting one today means `pdq`, a Python `libnetflow`
notebook, or Suricata in PCAP mode. This extension makes the decoder a SQL
primitive: the datagram is a `BLOB` column, the header fields come back as a
`STRUCT` you can filter / join / aggregate on. Use it for sequence-gap
analysis over a column of datagrams, export-version triage, and well-formedness
screening of raw capture blobs before a heavier decode.

## Functions

| Function | Returns | Notes |
|---|---|---|
| `netflow_version(payload)` | `VARCHAR` | `'5'` / `'9'` / `'10'` / `'sflow5'`, or `NULL` when the leading bytes match no known flow header. |
| `netflow_header(payload)` | `STRUCT(version, count, sys_uptime, export_time, sequence, obs_domain)` | The export header only (no record decode). `export_time` is `TIMESTAMPTZ` (microseconds since the Unix epoch). IPFIX / sFlow fields map best-effort (`count` / `sys_uptime` may be `NULL`). All fields `NULL` when the blob is not a flow datagram. |
| `netflow_well_formed(payload)` | `STRUCT(ok, version, error, kind)` | Structural validation without a full decode. `kind` is one of `truncated`, `bad-version`, `set-length-overrun`, `bad-ipfix-set`, `short-record`, `not-a-flow-datagram` (or `NULL` when `ok`). |

`payload` is a `BLOB` holding **one** flow-export datagram (header + its
records). All three functions are total on arbitrary input: a non-flow or
truncated blob yields `NULL` / an all-`NULL` struct / `ok=false` with a
classified `kind` — never a SQL error.

### A note on `netflow_well_formed` for NetFlow v5

The core parses a 22-byte v5 header but validates against the 24-byte
on-wire header: it requires `24 + count * 48` bytes total. A datagram whose
record region is two bytes short is reported as `ok=false` with
`kind='short-record'` — even though the header itself decodes fine
(`netflow_version` and `netflow_header` still return values).

## Scope (v1)

- **Header-level scalars only** — the VGI worker's `templates` table and any
  per-record / per-flow decode are not ported; this is the cheap probe +
  triage surface. Feed datagram BLOBs in directly.
- **No per-record output** — decoding individual flow records (5-tuples,
  byte/packet counts) is left for a later surface; v1 is version + header +
  well-formedness.

## Build

```sh
make release        # -> target/release/netflow.duckdb_extension
make test           # bundled DuckDB runs tests/integration.rs (SQL-level)
```

The cdylib links only the DuckDB C extension ABI (resolved at `LOAD` time) and
`netflow_core` (pure Rust, no native, no I/O). `panic = "unwind"` keeps a bug
in the extension from aborting the host process.
