# documentdb-wal-audit

Native C offline inspection of PostgreSQL WAL from unmodified
[DocumentDB](https://github.com/documentdb/documentdb), using PostgreSQL's
`XLogReader` and libbson. No Python runtime, database connection, replication
slot, extension changes, triggers, or audit tables are required.

## Scope

The initial core reads WAL with matching PostgreSQL frontend support,
reconstructs transaction outcomes, and reports ordinary physical heap effects.
An optional relation manifest supplies DocumentDB namespace mappings and
enables decoding of available ordinary tuple/BSON bytes.
Recognized ordinary heap inserts and multi-inserts, updates (including HOT
updates), and deletes become document events. Other records can be reported with
`--show-postgres-records`; without a manifest there are no named document
events.
Version 2 manifests can also identify
`documentdb_api_catalog.collections`. The decoder reconstructs available
ordinary and multi-insert catalog tuples, folds committed transaction and
subtransaction mutations, and emits inferred database/collection/view create,
rename, and drop lifecycle events. These are catalog state transitions, never
claims about the original MongoDB command.
Transaction handling includes subtransaction attribution and prepared
commit/rollback outcomes when the required records are present; a prepare
record alone is not a known commit.

Physical effects are not the original MongoDB command. WAL can omit old tuple
images, document bytes, transaction outcomes, and historical relation mappings.
Missing information remains unresolved rather than invented.

Prefix/suffix heap updates are reconstructed with PostgreSQL-major-specific
redo rules when the predecessor TID is available from prior WAL or a restored
full-page image in the private SQLite cache. The recovered tuple is decoded
through the same BSON validator as a fully logged tuple; `before` remains null
unless WAL independently logged it.

**Not shipped:** full TOAST reconstruction, index lifecycle decoding, offline
data-directory (`pgdata`) bootstrap, and complete maintenance/pruning coverage.
The expanded interfaces in [design.md](design.md) are proposals, not current
CLI instructions.

## One-command mongosh demo

From this repository, with Docker or Podman running:

```bash
./scripts/demo.sh
# Or select the runtime explicitly:
CONTAINER_RUNTIME=docker ./scripts/demo.sh
```

The script prefers Podman when both CLIs are installed. It pulls the public
PostgreSQL 17 DocumentDB-local image, a Mongo image **only for `mongosh`**, and jq,
builds the audit image, and starts a separate disposable database. Nothing is
installed on your host, and existing databases are not accessed.
The default DocumentDB image is pinned to multiarch digest
`sha256:906670c630fc94e97b310a4951c5c0b81cb2853de4ccb21f75808031d4e2714d`
from public `v1.0-RC2` commit
`b0cb0dae85e8746f4e0b79c847894179b2f80d64`; the script verifies extension
version `1.0-0`.

Watch six steps: start DocumentDB, connect with `mongosh`, create a collection,
insert three documents, update/replace/delete documents and create/drop an
index, then capture closed WAL and run the audit container. The script compares
all six document effects and every available BSON value against Mongo read-back,
prints decoded events, and reports complete versus explicitly incomplete images.
Step 4 uses containerized `jq` to pretty-print Mongo read-back as canonical
Extended JSON. The final report also uses jq for the decoded WAL document
effects and verification summary. The logical database is created implicitly by
`createCollection()`; step 3 shows the command and verifies both exist.
WAL capture begins before creation. The final report uses jq to show
WAL-derived `databaseCreate` and `collectionCreate` catalog events and fails if
either is absent. It rejects the former demo-injected `mongosh-observed`
substitutes. `setup-catalog-records.jsonl` retains the underlying physical
catalog records for inspection.
It preserves the image's default WAL settings. The demo requires update and
replacement `objectId` and `after` values to match mongosh exactly; unavailable
old/delete images remain explicit. Lifecycle events infer committed catalog
transitions but never claim the original DDL command.

WAL, the collection manifest, Mongo expectations, and `audit.jsonl` are retained
under ignored `demo-output/wal-audit-demo-*/` directories for inspection.
Demo-owned containers, network, and database volume are removed on exit,
including failure. No ports are published; `mongosh` connects within the private
container network. `DOCUMENTDB_IMAGE` can override the public image with another
compatible PG17 image; `MONGOSH_IMAGE` overrides the shell image.
`JQ_IMAGE` overrides the jq image.

## Build with containers

PostgreSQL **18 is the default**. Compile a separate executable for PostgreSQL
**17 or 16**; the executable must match the major that produced the WAL.
`--postgres-major N` is an optional assertion that must match the compiled
major; it cannot select a different decoder or convert WAL formats.

With Podman on macOS, use its Linux virtual machine:

```bash
podman machine start
podman build --build-arg PG_MAJOR=18 -t documentdb-wal-audit:pg18 .
podman run --rm documentdb-wal-audit:pg18 --help
```

Initialize the Podman machine first with `podman machine init` if none exists.
Docker is an alternative; it uses the same Dockerfile:

```bash
docker build --build-arg PG_MAJOR=18 -t documentdb-wal-audit:pg18 .
docker run --rm documentdb-wal-audit:pg18 --help
```

For a PostgreSQL 17 image:

```bash
podman build --build-arg PG_MAJOR=17 -t documentdb-wal-audit:pg17 .
```

Use `PG_MAJOR=16` and a `:pg16` image tag for PostgreSQL 16.
The Makefile defaults to `PG_MAJOR=18`; inside the build container,
`make PG_MAJOR=17` compiles the PostgreSQL 17 executable at
`build/pg17/documentdb-wal-audit`.

The build downloads pinned PostgreSQL 18.0, 17.0, or 16.0 source from official
mirrors, verifies the published SHA-256 checksum, and compiles matching frontend
support. C build tools,
`libbson-dev`, `libsqlite3-dev`, and test-only Python are installed **inside the container**.
Do not install PostgreSQL or dependencies on the host through Homebrew.
The runtime image runs non-root with the binary at
`/usr/local/bin/documentdb-wal-audit` as its entrypoint.

### Development tests

Build the test stage to run Python `unittest` integration tests as the
container's non-root PostgreSQL user:

```bash
podman build --target test --build-arg PG_MAJOR=18 \
  -t documentdb-wal-audit-tests:pg18 .
```

Substitute `docker` for `podman` if preferred, or change `PG_MAJOR` and the tag
for 17 or 16. Tests exercise synthetic WAL and WAL produced by the matching
real PostgreSQL server. The ordinary BSON integration fixture uses `bytea`
columns with the relevant physical storage layout; it does **not** load the
DocumentDB extension or establish full extension-version compatibility.
Python is only a development-test dependency.

### Mongo end-to-end test

```bash
podman build --target toolchain --build-arg PG_MAJOR=17 \
  -t documentdb-wal-audit-toolchain:pg17 .
podman run --rm --entrypoint sh -v "$PWD:/src" -w /src \
  documentdb-wal-audit-toolchain:pg17 \
  -c 'make -j2 PG_MAJOR=17 all native-test'
tests/mongo/runner.sh
```

Uses Podman only: the pinned multi-platform PostgreSQL 17 image published from
public [DocumentDB `v1.0-RC2`](https://github.com/documentdb/documentdb/tree/v1.0-RC2)
(extension `1.0-0`), its native Mongo gateway, and container-only PyMongo
3.11.0. The commands above build the matching Linux executable at
`build/pg17/documentdb-wal-audit` and its PostgreSQL 17 toolchain container.
`DOCUMENTDB_IMAGE` and `AUDIT_TOOLCHAIN_IMAGE` override these images;
`EXPECTED_DOCUMENTDB_VERSION` overrides the required extension version;
the producing PostgreSQL major is detected and must match the Linux executable.
No host database, Python installation, or published ports are used.

The runner checks acknowledged single/batch inserts, update, replacement,
delete, index create/drop, collection rename, and cleanup against actual Mongo
reads. Read-only SQL `COPY` captures closed WAL segments; public catalogs supply
cluster provenance and separate half-open manifests before/after rename.
Committed effect counts, namespaces, order, available canonical BSON images/IDs,
and JSONL redaction are compared with driver-observed results.

Two isolated passes run: **default** preserves the image's WAL/replica-identity
settings and asserts explicit warnings for unavailable physical images;
**precision** uses test-only `wal_level=logical` and
`REPLICA IDENTITY FULL` to require complete before/after BSON with `--strict`.
These fixture settings are not required by the offline runtime.
`MONGO_WAL_MODE=default` or `precision` selects one pass.
DDL is exercised through Mongo. Collection catalog transitions are decoded,
while original command intent and index lifecycle decoding remain unsupported.

Each run uses a private internal network and unique container/volume names,
disables telemetry, and cleans up its containers/network/volume on failure too.
Synthetic-only WAL, manifests, expected values, JSONL, and summaries remain in
ignored `tests/mongo/artifacts/`; credentials are not archived.

## Native build on a Linux server

You can also compile and run directly on a Linux server; Docker and a local
PostgreSQL development installation are not required. On Debian or Ubuntu,
copy or check out this repository, then run from its root:

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

For example, with an immutable archive at `/srv/documentdb-wal-archive` and
a matching manifest at `/srv/documentdb-wal-manifest.json`, run as the account
that can read them. This example uses `postgres`; substitute the actual data
owner if your deployment uses another account:

```bash
sudo install -d -o postgres -g postgres -m 0700 /srv/wal-audit-spill
sudo -u postgres "/usr/local/bin/documentdb-wal-audit-pg${PG_MAJOR}" \
  --wal-dir /srv/documentdb-wal-archive \
  --manifest /srv/documentdb-wal-manifest.json \
  --spill-dir /srv/wal-audit-spill \
  --format jsonl > audit.jsonl
```

The installed executable is major-specific, just like the container image.
Use archived WAL or a consistent snapshot, not a live server's changing
`pg_wal` directory. A mounted data directory alone does not supply collection
mappings: automatic `--pgdata` discovery is not implemented. Without a
manifest, use `--show-postgres-records` for physical inspection instead of
named document events. On macOS, use the container build above; these package
installation commands are for Linux servers only.

## Offline use

Work with archived WAL or an immutable backup copy, not files actively being
written by a running server. Retain contiguous input and provenance: cluster,
timeline, segment size, and PostgreSQL major. Do not mix clusters or divergent
timelines.

Mount input WAL read-only. Output goes to stdout so the host can redirect it
without granting the runtime write access to the archive. Transaction spooling
needs writable storage separate from the input.

For a local `wal/` archive and separate `spill/` directory, run from a non-root
host account. Matching the container UID/GID to that account allows it to own
the private spill directory:

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

The same command works with `docker` in place of `podman`; ensure the container
user can read the archive and owns the spill directory. Bind-mount access and
UID mapping depend on the container runtime. Do not solve spill access errors
by making sensitive directories world-writable.
For rootless Podman, `--userns keep-id` may be needed to preserve the archive
owner's identity. Preserve private backup permissions; do not make WAL
world-readable to accommodate the container.

For small workloads, an alternative is a private RAM-backed spool using the
image's default UID/GID 65534:

```bash
podman run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  -v "$PWD/wal:/wal:ro" \
  --tmpfs /spill:rw,mode=0700,uid=65534,gid=65534 \
  documentdb-wal-audit:pg18 \
  --wal-dir /wal --spill-dir /spill --format jsonl > audit.jsonl
```

This requires that UID 65534 can already read the archive. A tmpfs consumes
memory and is not a substitute for disk-backed spooling on large workloads;
prefer a private owned host spool mount when logs or transactions are large.

Use **either** `--wal-dir DIRECTORY` **or** positional segment paths, never
both. To attach a manifest, mount its file read-only and add
`--manifest /path/in/container/manifest.json`.

### CLI

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

Size arguments are positive decimal byte counts, without unit suffixes.
The record minimum is 24 bytes. LSN bounds must be ordered (`from < to`) and
use record boundaries, not arbitrary byte offsets. A range that excludes
required transaction outcomes can leave effects unresolved; filtering is not
a promise of complete transaction recovery.

Exit statuses are **0** for success, **1** for reading/decoding/output errors,
and **2** for invalid arguments. Keep stderr separate from JSONL stdout.
Output preceding an error is partial; a nonzero exit status must not be ignored.
Transactions lacking an outcome at end of input fail even when a transaction
filter would hide their summaries. Without `--strict`, incomplete document
reconstruction is reported with warnings; corruption and unresolved
transaction outcomes still fail. `--strict` also makes incomplete document
reconstruction fail, including missing old images for ordinary updates/deletes.

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
