# documentdb-wal-audit

Native C offline inspection of PostgreSQL WAL from unmodified
[DocumentDB](https://github.com/documentdb/documentdb), using PostgreSQL's
`XLogReader` and libbson. No Python runtime, database connection, replication
slot, extension changes, triggers, or audit tables are required.

## Use the command-line tool

The executable reads archived WAL, writes audit events to stdout, and writes
diagnostics to stderr. Use the binary compiled for the PostgreSQL major that
produced the WAL.

Inspect physical PostgreSQL records:

```bash
documentdb-wal-audit-pg17 \
  --wal-dir /srv/documentdb-wal-archive \
  --show-postgres-records
```

Decode DocumentDB events as JSON Lines by supplying a relation manifest:

```bash
install -d -m 0700 "$HOME/wal-audit/spill"
documentdb-wal-audit-pg17 \
  --wal-dir /srv/documentdb-wal-archive \
  --manifest /srv/documentdb-wal-manifest.json \
  --spill-dir "$HOME/wal-audit/spill" \
  --format jsonl > audit.jsonl
```

For a long-running audit, add a persistent cache so later WAL can reconstruct
catalog state and update after-images from earlier records:

```bash
install -d -m 0700 "$HOME/wal-audit/state"
documentdb-wal-audit-pg17 \
  --wal-dir /srv/documentdb-wal-archive \
  --manifest /srv/documentdb-wal-manifest.json \
  --spill-dir "$HOME/wal-audit/spill" \
  --cache "$HOME/wal-audit/state/cache.sqlite" \
  --format jsonl > audit.jsonl
```

If the cache is lost and the archive contains contiguous WAL from the beginning
of the retained history, rerun with `--rebuild-cache`. Use either `--wal-dir`
or positional segment paths, never both. Read immutable archived WAL rather
than a live server's changing `pg_wal` directory.

### Options

| Option | Meaning |
|---|---|
| `--format text\|jsonl` | Text by default; JSON Lines for machine-readable output |
| `--postgres-major N` | Assert the compiled major, 16, 17, or 18 |
| `--from-lsn HEX/HEX` | Inclusive lower record boundary |
| `--to-lsn HEX/HEX` | Exclusive upper record boundary |
| `--transaction N` | Positive decimal 32-bit transaction ID |
| `--manifest FILE` | Validated relation manifest |
| `--spill-dir DIRECTORY` | Private transaction spool directory |
| `--cache FILE` | Persistent SQLite catalog and physical tuple-history cache in a private 0700 parent |
| `--rebuild-cache` | Rebuild a sibling candidate and replace `--cache` only after success |
| `--no-persistent-cache` | Use process-local SQLite catalog/page state (the default) |
| `--ephemeral-cache DIRECTORY` | Use and remove a disposable 0600 catalog/page cache in a private 0700 directory |
| `--max-record-bytes N` | Record limit, default 67,108,864 bytes |
| `--max-transaction-bytes N` | Transaction buffering limit, default 67,108,864 bytes |
| `--max-document-bytes N` | BSON attribute limit, default 16,777,216 bytes |
| `--include-aborted` | Include physical effects of aborted transactions |
| `--strict` | Fail on incomplete requested decoding |
| `--show-postgres-records` | Include otherwise unreported PostgreSQL records |
| `--redact-documents` | Suppress document values |
| `--version`, `--help` | Display build version or help |

Exit statuses are **0** for success, **1** for reading/decoding/output errors,
and **2** for invalid arguments. Keep stderr separate from JSONL stdout.
Output preceding an error is partial. Without `--strict`, unavailable document
images are reported with warnings; corruption and unresolved transaction
outcomes still fail.

## Run the demo

From this repository, with Docker or Podman running:

```bash
./scripts/demo.sh
# Or select the runtime explicitly:
CONTAINER_RUNTIME=docker ./scripts/demo.sh
```

The script starts a disposable DocumentDB instance, runs a `mongosh` workload,
captures its closed WAL, builds the audit tool, and verifies the decoded
insert, update, replacement, and delete events against Mongo read-back. It also
requires WAL-derived database and collection lifecycle events.

The demo uses the public DocumentDB `v1.0-RC2` PostgreSQL 17 image and installs
nothing on the host. It publishes no ports and removes its containers, network,
and volume on exit. WAL, the generated manifest, expected values, and
`audit.jsonl` remain under ignored `demo-output/wal-audit-demo-*/` directories.
`DOCUMENTDB_IMAGE`, `MONGOSH_IMAGE`, and `JQ_IMAGE` can override the defaults.

## Compile on Linux

On Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential bison flex pkg-config \
  libbson-dev libsqlite3-dev curl ca-certificates bzip2 perl

# Match the PostgreSQL major that produced the WAL: 16, 17, or 18.
PG_MAJOR=17
make -j2 PG_MAJOR="$PG_MAJOR" all native-test
sudo install -m 0755 "build/pg${PG_MAJOR}/documentdb-wal-audit" \
  "/usr/local/bin/documentdb-wal-audit-pg${PG_MAJOR}"

"/usr/local/bin/documentdb-wal-audit-pg${PG_MAJOR}" --version
```

The build downloads and verifies matching PostgreSQL source and compiles its
frontend support; it does not install or modify a PostgreSQL server. Omitting
`PG_MAJOR` selects 18. Python is not required to build or run the tool.
Keep the runtime `libbson` and SQLite libraries installed.
The installed executable is major-specific. A data directory alone does not
supply collection mappings; named document events require a manifest.
On macOS, use the container build described below.

## Scope

The tool recognizes ordinary heap inserts, multi-inserts, updates, HOT updates,
and deletes. A manifest maps physical relations to DocumentDB namespaces and
enables BSON document events. Version 2 manifests also identify the collections
catalog, allowing inferred database, collection, and view create, rename, and
drop events.

The SQLite cache retains catalog and tuple history across runs. It reconstructs
prefix/suffix update after-images when earlier WAL or a full-page image supplied
the predecessor tuple. Missing data remains explicit rather than invented.

WAL records physical effects, not the original MongoDB command. Full TOAST
reconstruction, index lifecycle decoding, `pgdata` bootstrap, and complete
maintenance/pruning coverage are not implemented. See [design.md](design.md)
for architecture and planned interfaces.

## Relation manifest

Schema version 1 binds document relations. Schema version 2 additionally binds
the collections catalog. Both bind physical
relation identifiers to DocumentDB namespaces for one cluster, timeline,
PostgreSQL major, and half-open LSN interval:

```json
{
  "schemaVersion": 2,
  "postgresMajor": 17,
  "systemIdentifier": "1234567890123456789",
  "timeline": 1,
  "documentdbVersion": "1.0-0",
  "validFromLsn": "0/1000000",
  "validToLsn": "0/2000000",
  "relations": [
    {
      "kind": "collections_catalog",
      "tblspaceOid": 1663,
      "databaseOid": 5,
      "relfilenode": 18468
    },
    {
      "kind": "document",
      "tblspaceOid": 1663,
      "databaseOid": 5,
      "relfilenode": 24576,
      "collectionId": 42,
      "database": "example",
      "collection": "items"
    }
  ]
}
```

Values above are illustrative, not mappings for a real installation. Supply
the producing cluster's actual system identifier as a decimal **string**,
its major and timeline, the actual extension version, physical identifiers,
and the interval in which the mapping is valid. `validFromLsn` is inclusive;
`validToLsn` is exclusive. Do not extend validity across relation rewrites,
drops, or relfilenode reuse. Outside the interval the relation is unresolved.

All fields shown are required. Names and `documentdbVersion` are nonempty
strings; identifiers are positive integers except `systemIdentifier`.
Unknown or duplicate keys, duplicate physical relation mappings, invalid
types, and major mismatches are rejected. Manifest size is limited to 16 MiB
and 100,000 relation entries. For schema version 2, `kind` is required. A `document` entry requires
`collectionId`, `database`, and `collection`; a `collections_catalog` entry
forbids them. Catalog decoding currently recognizes exact public extension
versions `0.100-0` through `0.114-0` (except nonexistent `0.115-0`),
`0.116-0`, `0.117-0`, and `1.0-0`, with their validated 9- or 10-attribute
descriptors. Other exact versions fail closed.
Manifest numeric fields require plain JSON integers, not Extended JSON
wrappers such as `{"$numberInt":"18"}`.

Ordinary BSON decoding requires a recognized tuple layout with
`shard_key_value`, `object_id`, `document`, and optionally `creation_time`.
The required attributes cannot be NULL. BSON is validated with libbson and
the single empty-key value in `object_id` must match the document's `_id`.
DocumentDB stores this projected identifier as `{"": value}`; audit output
normalizes it to `{"_id": value}` without changing the BSON value's type.
For logged replica-identity old-key tuples, `objectId` is recovered separately
when its ordinary BSON bytes are present, even if the shard key or document
attribute is NULL. The missing before-image remains incomplete; recovering an
identifier does not imply recovering a document.
External TOAST and compressed BSON are unresolved; this is not an arbitrary
BSON-byte scanner or a full TOAST decoder. Valid heap full-page images seed
tuple history. Prefix-only, suffix-only, and combined update deltas use the
old TID only when its trusted predecessor bytes exist; malformed deltas,
missing TIDs, untrusted state after a gap, moved-page delta flags, and invalid
HOT movement remain explicit incomplete events.
Ordinary multi-insert records emit an insert event per available tuple;
an image-only multi-insert instead emits an incomplete event with `tupleCount`.
An available after-image does not imply an old image is also available.

## Output contract

JSONL is one JSON object per line, with `schemaVersion: 1`. Text mode prefixes
the same JSON representation with the operation/event kind and
`transaction=<id>`; it is not an independent tabular schema.

Normal events have these fields:

| Field | Contract |
|---|---|
| `eventType` | `document`, `catalog`, `transaction`, or `postgresRecord` |
| `certainty` | `certain`, `inferred`, `physical`, or `incomplete` |
| `operation` | Document or catalog lifecycle operation, `unknown`, or `null` |
| `timestamp` | Outcome timestamp in ISO 8601 UTC, or `null` |
| `timeline`, `transactionId` | Numeric PostgreSQL identifiers |
| `eventLsn` | Record LSN as a hexadecimal `HEX/HEX` string |
| `commitLsn` | Commit record LSN for committed events; otherwise `null` |
| `database`, `collection`, `collectionId` | Manifest namespace values, or `null` |
| `objectId`, `before`, `after` | Canonical BSON Extended JSON when available; otherwise `null` |
| `warnings` | Array of diagnostic strings |

Resolved transactional events also have `outcome: "committed"` or
`"aborted"`; unresolved summaries have `"unresolved"`. Standalone PostgreSQL
records may lack `outcome`. Document events have a `relation` object containing
`tblspaceOid`, `databaseOid`, `relfilenode`, and `block`. PostgreSQL physical
record events additionally expose numeric `resourceManager`, `recordInfo`,
`recordBytes`, and `mainDataBytes`; their `relation` is `null`. Their `blocks`
array contains each reference's `blockId`, `tblspaceOid`, `databaseOid`,
`relfilenode`, `fork`, `block`, `dataBytes`, and boolean `hasImage`.
Transaction summaries need not contain `relation`.
Catalog events use namespace-summary objects for `before` and `after`, and add
`coverage`, `descriptorFingerprint`, `isView`, and an `evidence` array.
Coverage is `row-local` for a fresh mid-history cache, degrades to `partial`
after missing required state, and is persisted with reusable caches. An
unavailable predecessor emits `operation: "unknown"` with a stable warning;
`--strict` fails when such an event is in the requested range.
Reconstructed update events add a `reconstruction` object describing the redo
method, prefix/suffix byte counts, and predecessor state LSN.

BSON values preserve type information; for example, an int32 appears as
`{"$numberInt":"1"}` inside a document, while event identifiers are ordinary
JSON numbers. Redaction sets `objectId`, `before`, and `after` to `null`,
retaining namespace, outcome, and warning metadata. A null image can mean
absence, unsupported reconstruction, or redaction; consult warnings and the
invocation.

Effects are buffered until their outcome, grouped with their transaction,
and ordered by effect LSN within that transaction. Transaction groups follow
outcome WAL order, not a global ordering of all effect LSNs.
Aborted transaction summaries are emitted by default; their effects require
`--include-aborted`. Neither aborted nor unresolved output is committed data.
Known savepoint subtransactions do not emit separate transaction summaries.
Their aborted effects, when requested, retain the physical subtransaction ID
and include `parentTransactionId`; selecting the parent also selects these
effects. Unresolved known children are reported through their parent summary.
`certain` labels available physical values and known outcomes, not original
MongoDB command intent or an independently verified namespace mapping.

Errors use a smaller object: `schemaVersion`, `eventType: "error"`,
`certainty: "incomplete"`, `message`, `eventLsn`, and `transactionId: 0`.
The tool also reports the error on stderr and exits nonzero. Consumers must
handle errors and inspect the process exit status, not merely parse lines.

## Resource limits and performance

The reader streams WAL instead of loading the entire archive into memory.
`--max-transaction-bytes` bounds **aggregate retained event buffering across
active transactions**, not the total size of a single transaction or the
process's complete memory footprint. When the threshold is exceeded, pending
effects are spooled to disk under `--spill-dir`. Transactions can exceed the
threshold with sufficient spill storage; without a spill directory the tool
fails explicitly instead of growing the retained event buffer without bound.

The spill directory must already exist, be a non-symlink directory owned by
the executing UID, and have mode **0700**. Spool files use mode **0600** and are
removed on normal resolution and decoder cleanup. Abrupt process termination
can leave files behind; inspect and securely clean the dedicated spill
directory after a crash. Disk usage is not bounded by the buffering threshold.

Cache parent directories have the same owner-only 0700 requirement; cache
files are regular owner-owned 0600 files. The single SQLite store contains
both committed catalog state and LSN-versioned physical heap tuple history.
Cache provenance binds the
cluster system identifier, PostgreSQL major, block and WAL segment sizes,
timeline, exact DocumentDB version, and descriptor fingerprint. Mutations are
staged until commit, discarded on abort, retained across prepare, and
reparented with subtransactions. Replaying exact mutation LSN/ordinal entries
is idempotent; physical tuple versions make exact overlap replay deterministic.
Heap redo state advances for committed and aborted physical effects; audit
event visibility still follows transaction outcome and filters.
`--rebuild-cache` leaves the active
cache untouched until the complete run succeeds and then atomically renames
the candidate.

The decoder allows at most 4,096 active transactions. Record and document
limits bound individual decoding allocations, in addition to transaction
bookkeeping and temporary rendering buffers. Provision spill storage for
pending transactions and protect it like the WAL itself.

No throughput or speedup is claimed. Archive storage, transaction size,
BSON rendering, and output volume affect performance. Measure representative
workloads and size output and spool storage accordingly.

## Build with containers

PostgreSQL 18 is the default. Set `PG_MAJOR` to 16 or 17 to build a matching
binary for WAL produced by those versions.

```bash
podman machine start
podman build --build-arg PG_MAJOR=18 -t documentdb-wal-audit:pg18 .
podman run --rm documentdb-wal-audit:pg18 --help
```

Docker uses the same Dockerfile:

```bash
docker build --build-arg PG_MAJOR=18 -t documentdb-wal-audit:pg18 .
docker run --rm documentdb-wal-audit:pg18 --help
```

To audit a local archive while keeping it read-only:

```bash
mkdir -p spill
chmod 700 spill
podman run --rm --user "$(id -u):$(id -g)" \
  --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  -v "$PWD/wal:/wal:ro" -v "$PWD/spill:/spill:rw" \
  documentdb-wal-audit:pg18 \
  --wal-dir /wal --spill-dir /spill --format jsonl > audit.jsonl
```

### Development tests

```bash
podman build --target test --build-arg PG_MAJOR=18 \
  -t documentdb-wal-audit-tests:pg18 .
```

### Mongo end-to-end test

```bash
podman build --target toolchain --build-arg PG_MAJOR=17 \
  -t documentdb-wal-audit-toolchain:pg17 .
podman run --rm --entrypoint sh -v "$PWD:/src" -w /src \
  documentdb-wal-audit-toolchain:pg17 \
  -c 'make -j2 PG_MAJOR=17 all native-test'
tests/mongo/runner.sh
```

The runner uses the public
[DocumentDB `v1.0-RC2`](https://github.com/documentdb/documentdb/tree/v1.0-RC2)
image and verifies decoded events against real Mongo reads. Set
`MONGO_WAL_MODE=default` or `precision` to run one mode instead of both.
Artifacts remain under ignored `tests/mongo/artifacts/`.

## Data handling

WAL can contain sensitive current and deleted document data. Treat input,
spill files, and output as backups. Protect permissions and do not upload them
to third-party services. Document redaction suppresses document values, not
all potentially sensitive metadata; inspect output before sharing it.

Corrupt, discontinuous, malformed, or unsupported input must not silently
produce a claim of complete auditing. Unresolved physical effects are not
known committed document operations. This tool does not replace point-in-time
recovery or provide compliance-grade semantic auditing.

## License

The project's own code uses the [MIT License](LICENSE).
PostgreSQL-derived source and frontend support retain the PostgreSQL License;
libbson retains its Apache License 2.0 terms. Dependency licenses are separate
from the project's MIT License.
