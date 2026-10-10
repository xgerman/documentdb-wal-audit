# Standalone Offline WAL Inspection Tool Design

## Status

This RFC defines both the initial implementation scope and a proposed complete
design for `documentdb-wal-audit`, an open-source command-line tool for
inspecting DocumentDB PostgreSQL write-ahead log (WAL) files offline.

**Implementation:** a native C command-line program using PostgreSQL's
`XLogReader` and libbson. Python is used only for development tests, not at
runtime. Build and test inside Linux containers; no host PostgreSQL, Homebrew,
or host package installation is required.

PostgreSQL **18 is the default build**. PostgreSQL **16 and 17** require their
own matching builds (`make PG_MAJOR=16` or `make PG_MAJOR=17` inside the build
container). A binary must match the major that produced its WAL.
`--postgres-major` only asserts that match; it cannot switch the compiled
decoder. The default is not automatic version detection.

### Stages and acceptance boundaries

| Stage | Scope | Status |
|---|---|---|
| Native core | Matching PostgreSQL `XLogReader`; validated WAL framing and checksums; transaction outcomes; ordinary physical heap effects; optional manifest-scoped namespace interpretation and ordinary BSON decoding; JSON/text output, LSN filters, redaction, bounded transaction spooling, and explicit errors | Initial implementation; exact interface and verified coverage documented in README |
| Collections-catalog decoder | Versioned decoding of `documentdb_api_catalog.collections`; committed collection/view lifecycle events learned from WAL; transaction-aware SQLite cache with persistent, rebuild, memory-only, and disposable modes; explicit range-boundary state and incomplete behavior | **Implemented for the validated ordinary tuple forms and descriptors documented in README** |
| Heap update reconstruction | One SQLite store for catalog plus LSN-versioned heap tuple/page state; insert/multi-insert/update/HOT/delete, storage create/truncate/drop lifecycle, full-page-image seeding, exact prefix/suffix redo, overlap replay, rebuild, and disposable modes | **Implemented for ordinary inline tuples and the constraints documented in README** |
| Complete offline interpretation | Full TOAST reconstruction, complete vacuum/pruning/gap coverage, index-catalog interpretation, optional offline data-directory bootstrap, cache checksums/resource ceilings, and broader filters | Proposed, not shipped |

The shipped native core must report unavailable tuple images, external TOAST values,
unresolved relations, and unknown transaction outcomes explicitly rather than
claiming complete document recovery or logical command intent. Prepared
transactions, subtransactions, and specific heap variants must not be advertised
as supported until their implementations and tests confirm coverage.

The shipped collections-catalog decoder is deliberately narrower than the
remaining complete design: it does
not add index decoding, an offline data-directory reader, or recovery of original
MongoDB commands. Other complete-design examples, options, and output fields are
**proposed interfaces** unless the README explicitly confirms them as shipped.

## Problem

DocumentDB does not provide an offline tool that explains PostgreSQL
write-ahead log (WAL) in DocumentDB terms. Existing PostgreSQL tools display
physical records such as heap inserts, page updates, commits, and relation
identifiers, but they do not answer:

- Which DocumentDB document table changed?
- Was the physical effect an insert, update, or delete?
- Is the BSON document or `_id` available in the supplied WAL?
- Which changes committed together?
- Did DocumentDB collection or index metadata change?
- Which information is certain, inferred, or unavailable?

The tool must work against an unmodified DocumentDB installation. Version 1
must not require:

- triggers;
- extension changes;
- additional tables;
- audit hooks or logical messages;
- replication slots;
- a running PostgreSQL server;
- a database connection.

The implementation lives in this repository and consumes WAL produced by
released DocumentDB versions.

### What unmodified WAL can provide

Validated WAL can provide physical and transaction information, subject to
record coverage and continuity of the supplied input:

- WAL position and ordering;
- PostgreSQL resource manager and record type;
- transaction and subtransaction IDs;
- commit, abort, and prepared-transaction outcome;
- relation and block identifiers;
- physical heap insert, update, delete, and truncate effects;
- checkpoint, timeline, and segment continuity information.

When the required tuple bytes are present, the known DocumentDB table layout
allows the tool to additionally reconstruct:

- `shard_key_value`;
- `object_id`;
- the BSON `document`;
- the resulting document for many inserts and updates.

The target collections-catalog decoder may infer changes from available,
committed DocumentDB catalog tuples to:

- databases and collections;
- collection names and IDs;
- views recorded in the collections catalog.

Index metadata remains a later target. These are inferred state transitions,
not recovered commands. This design does not assume undocumented user, role,
or sharding catalog relations.

### What unmodified WAL cannot guarantee

Bare WAL does not reliably preserve:

- the original MongoDB command or SQL statement;
- the authenticated DocumentDB principal or client request ID;
- update-versus-replace intent;
- update predicates or update expressions;
- old documents for every update or delete;
- historical relation-to-collection mappings when the relevant catalog WAL is
  outside the supplied range;
- complete TOAST values whose earlier chunks are outside the supplied range;
- human-readable DDL intent from PostgreSQL catalog page changes alone.

The tool must never invent these values. Missing information is part of the
output contract.

### Success criteria

The feature is successful when a user can point the CLI at WAL from an
unmodified DocumentDB instance and receive:

- ordered committed and aborted transaction summaries;
- physical DML against recognized DocumentDB relations;
- BSON document and object ID values when reconstructable;
- best-effort collection and index metadata changes;
- explicit certainty and completeness labels;
- stable human-readable and JSON Lines output;
- non-zero exit status for unsafe gaps or corruption.

### Non-goals

The complete design does not:

- provide compliance-grade semantic auditing;
- recover data absent from the supplied WAL or optional snapshot;
- identify the authenticated MongoDB user;
- reproduce the exact original command;
- replace point-in-time recovery, change streams, or logical replication;
- decode arbitrary PostgreSQL application schemas;
- treat different PostgreSQL-major WAL layouts as interchangeable.

## Approach

The implementation provides a native CLI named `documentdb-wal-audit`.
PostgreSQL-major selection is a compile-time choice, with one container image
and executable per major.

```text
unmodified DocumentDB
          |
          v
    archived WAL segments
          |
          v
 documentdb-wal-audit
          |
     +----+---------+----------------+
     |              |                |
 physical facts   inferred events   warnings/gaps
     |
 text or JSON Lines
```

The C core uses matching PostgreSQL frontend source support rather than a
hand-written replacement for `XLogReader`. Its scope is validated physical
records and transaction outcomes, plus optional manifest-scoped DocumentDB
interpretation of available ordinary tuple/BSON bytes and the versioned
collections-catalog cache and ordinary inline heap page/update reconstruction.
It does not implement full TOAST reconstruction or every maintenance record
needed for indefinite-history physical replay.

WAL is streamed rather than loaded as a whole archive. `--max-transaction-bytes`
bounds aggregate retained event buffering across active transactions. Pending
effects spill to disk under `--spill-dir` when that threshold is exceeded;
without a spill directory the decoder fails explicitly. The threshold is not
a total transaction-size, disk-usage, or process-memory cap. The directory must
be owned by the executing UID with mode 0700; spool files use mode 0600.
Record and document size limits bound individual decoding allocations.
The initial decoder also caps active transactions at 4,096.
This is a resource-safety design, not a
claim of a measured throughput or speedup. Performance depends on archive
storage, transaction sizes, BSON rendering, and output volume; benchmark with
representative WAL before selecting operational limits.

No code changes are required in `pg_documentdb` or `pg_documentdb_core`.

### Reproducible container demo

`scripts/demo.sh` starts an isolated, disposable public DocumentDB-local
container and runs a synthetic workload through containerized `mongosh`.
The script starts WAL capture before collection creation, exports the collection
and collections-catalog physical mappings, switches WAL to close its segments, and
runs the matching audit image against an immutable read-only archive.
It compares reported effects and available BSON values with Mongo read-back.
Containerized jq pretty-prints read-back documents and WAL-derived inferred
`databaseCreate` and `collectionCreate` events. The demo rejects injected
client-observed lifecycle substitutes and fails if either event is absent.
The events describe committed catalog transitions, not original commands.
Default WAL settings are preserved. Update and replacement `after` documents
must reconstruct exactly from cached predecessor TIDs; genuinely missing
before/delete images remain explicit warnings.
Only demo-owned containers, network, and volume are cleaned up. The synthetic
archive, manifest, expected values, and output remain on the host for inspection.
Existing DocumentDB services are never selected or modified.

## Proposed Complete Design (Not the Initial Implementation)

Interfaces in this section illustrate the broader target, not the exact
current CLI or JSON schema; use the README and `--help` for the shipped core.
In particular, `--pgdata`, full TOAST recovery, cache checksum/resource-limit
features, and the complete CLI/schema below are not shipped features. The
README documents the shipped SQLite catalog/ordinary-page cache and CLI subset.

### Repository and implementation language

The tool lives in a separate public repository so it can:

- release independently from the database extension;
- build one artifact per PostgreSQL major;
- consume WAL from several DocumentDB releases;
- keep PostgreSQL-derived decoder code isolated;
- avoid adding runtime dependencies or attack surface to DocumentDB.

The implementation uses C because `XLogReader`, WAL record
definitions, checksum validation, timeline handling, and `pg_waldump` patterns
are PostgreSQL-version-specific C interfaces.

An illustrative expanded repository layout is:

```text
src/
  wal_reader.c
  transaction_decoder.c
  heap_decoder.c
  toast_decoder.c
  documentdb_schema.c
  bson_renderer.c
  event_writer.c
include/
schemas/
  documentdb-<version>.json
tests/
  fixtures/pg16/
  fixtures/pg17/
  fixtures/pg18/
```

The CLI links matching PostgreSQL source-level frontend support and libbson,
not `libpq`. The build obtains pinned PostgreSQL source releases from official
PostgreSQL mirrors and verifies their published checksums before compilation.
The default major is 18; matching 17 and 16 builds use the same process.

All dependencies and compilation live in Linux containers. The toolchain
includes C build tools, PostgreSQL frontend source support, and `libbson-dev`;
Python is present only for development tests. Runtime containers expose
`/usr/local/bin/documentdb-wal-audit` as their entrypoint and run non-root.
Mount WAL read-only and leave output on stdout; mount a separate writable
spill directory when required. See README for concrete Podman and Docker
commands.

### Input modes

#### WAL-only mode

```bash
documentdb-wal-audit --wal-dir /archive/pg_wal
```

This mode guarantees transaction and physical WAL facts. DocumentDB namespace
and BSON reconstruction are best effort.

#### WAL plus manifest

```bash
documentdb-wal-audit \
  --wal-dir /archive/pg_wal \
  --manifest documentdb-wal-manifest.json
```

The shipped strict manifest schema is version 1 and maps document relations.
The collections-catalog decoder requires a proposed version 2 while continuing
to accept version 1 for document-only decoding. Version 2 adds a required
`kind` discriminator to each relation entry:

```json
{
  "schemaVersion": 2,
  "postgresMajor": 17,
  "systemIdentifier": "7612345678901234567",
  "timeline": 1,
  "documentdbVersion": "0.117-0",
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
      "relfilenode": 19127,
      "collectionId": 6401,
      "database": "audit",
      "collection": "items"
    }
  ]
}
```

Version 2 remains strict: unknown or duplicate keys, duplicate physical
identities, unknown `kind` values, unsupported exact extension versions, and
overlapping contradictory mappings are errors. `documentdbVersion` uses the
exact `pg_extension.extversion` spelling, for example `0.117-0`; it is not a
claim that nearby semantic versions have the same tuple layout. A collection
command may generate the physical mapping without changing the database.
The manifest includes:

- PostgreSQL major version and system identifier;
- timeline and WAL segment size;
- DocumentDB extension version;
- relation OID and relfilenode mappings;
- relation kind and, for document relations, collection ID and namespace;
- TOAST relation mappings;
- validity LSN and creation timestamp.

The manifest supplies identity, not lifecycle observations. It must not contain
a list of expected creates, renames, or drops. Those events come from WAL.

#### Persistent sidecar cache

The complete design maintains a tool-owned physical reconstruction cache:

```bash
documentdb-wal-audit \
  --wal-dir /archive/pg_wal \
  --cache ~/.cache/documentdb-wal-audit/cluster.cache
```

Unlike a namespace-only catalog cache, this cache contains physical heap tuple
and page state and can therefore contain current and deleted document bytes.
Its format, provenance, transaction rules, rebuild modes, resource limits, and
invalidation behavior are specified in
[Update reconstruction and physical-state cache](#update-reconstruction-and-physical-state-cache).
The cache is an optimization and resumability mechanism, never the sole source
of truth: complete contiguous WAL retained from cluster initialization can
always rebuild it deterministically.

#### WAL plus offline data directory

```bash
documentdb-wal-audit \
  --wal-dir /backup/pg_wal \
  --pgdata /backup/base
```

The optional data directory must be a stopped copy or base backup. It is
opened read-only and can provide `pg_control`, relation mappings, and base
pages needed by some TOAST or update reconstructions. The tool must never
start PostgreSQL or create recovery state.

### Output certainty

Every event has one of four certainty levels:

| Level | Meaning |
|---|---|
| `physical` | Directly decoded PostgreSQL WAL fact |
| `certain` | Transaction outcome or exact value present in WAL |
| `inferred` | DocumentDB meaning inferred from known relation/schema layout |
| `incomplete` | Relevant record exists but required bytes or mapping are absent |

Example:

```text
2026-10-09T19:20:31.442Z [certain] COMMIT xid=7842 lsn=0/9A12F8
  [inferred] documentdb collection_id=42 operation=insert
    object_id: { "_id": { "$oid": "670819f..." } }
    document:  { "_id": { "$oid": "670819f..." }, "status": "new" }

2026-10-09T19:21:02.018Z [certain] COMMIT xid=7843 lsn=0/9A1840
  [incomplete] documentdb collection_id=42 operation=delete
    tuple: relation=1663/5/24891 block=17 offset=4
    warning: old document bytes are not present in the supplied WAL
```

### Transaction reconstruction

Concurrent transactions interleave in WAL. The decoder:

1. reads records sequentially with `XLogReader`;
2. groups relevant records by top-level transaction ID;
3. attaches subtransactions to their parent;
4. waits for commit or abort before emitting a semantic transaction;
5. discards semantic effects for aborted transactions by default;
6. emits aborted physical records with `--include-aborted`;
7. orders committed transactions by commit LSN;
8. supports `COMMIT PREPARED` and `ROLLBACK PREPARED`.

The output includes event LSN, commit LSN, transaction ID, timeline, and commit
timestamp when present.

### Relation recognition

The shipped decoder recognizes document relations only through a version 1
manifest. The target catalog decoder additionally recognizes:

- `documentdb_data.documents_<collection_id>`;
- each document table's TOAST relation;
- `documentdb_api_catalog.collections`;

Public collection-index metadata relations remain a later target.

Recognition sources, from strongest to weakest:

1. validated persistent sidecar cache;
2. supplied manifest;
3. relation/catalog state reconstructed within the WAL range;
4. read-only offline data directory;
5. known relfilenode mapping supplied manually;
6. unresolved physical identifier.

OID or relfilenode reuse must never inherit a stale name across a drop or
rewrite boundary.

### Document tuple decoding

Document tables have a known logical shape:

```text
shard_key_value bigint
object_id        bson
document         bson
creation_time    timestamptz, where present
```

The decoder maintains versioned tuple descriptors for supported DocumentDB
releases. It parses tuple headers, null bitmaps, alignment, varlena values, and
the DocumentDB BSON representation.

The public [`PgbsonGetDocumentId` and `BsonValueToDocumentPgbson`
helpers](https://github.com/documentdb/documentdb/blob/main/pg_documentdb_core/src/io/pgbson.c)
store `object_id` as `{"": value}`. The decoder validates that single projected
value against the document's `_id` and normalizes the audit `objectId` field
to `{"_id": value}`, preserving its BSON type.

Expected coverage:

| Operation | WAL-only result |
|---|---|
| Insert | New object ID and document when tuple bytes are present |
| Update | New document when the new tuple is present; old document may be absent |
| Delete | Physical relation/block/offset; old key or document only when logged |
| Truncate | Relation-level event |

The operation is reported as physical `update`; the tool cannot reliably
distinguish replacement from modifier update without additional metadata.

### Update reconstruction and physical-state cache

This section is the authoritative design for reconstructing an update's
resulting `after` document. It supersedes the narrower catalog-row cache
description. It assumes the operator retains complete, contiguous WAL from
cluster initialization for the lifetime of the cluster, potentially for years.
No PostgreSQL data directory or logical-decoding metadata is required for the
deterministic path.

An update event is complete only when its resulting ordinary DocumentDB tuple
and BSON document are reconstructed and validated. An available old document
is useful but optional. If the `after` tuple cannot be proved, the event is
`incomplete`, `after` is null, a stable reason is emitted, and `--strict`
fails. The decoder must never splice prefix/suffix bytes into an assumed empty,
zeroed, or manifest-synthesized page.

#### Current decoder gap

The native decoder currently reconstructs inserts and multi-inserts from
separately logged tuple data and updates only when PostgreSQL logs a complete
new tuple. It reports full-page-image-only inserts and multi-inserts as
unavailable and explicitly rejects `XLH_UPDATE_PREFIX_FROM_OLD` and
`XLH_UPDATE_SUFFIX_FROM_OLD`. It does not retain page state between records,
extract tuples from full-page images, process heap truncate, or model relation
generations. The implementation described below is therefore a later stage,
not shipped behavior.

#### PostgreSQL 16, 17, and 18 record contract

Each native build uses that major's PostgreSQL headers and redo rules; cache
records are never shared across majors. For the DocumentDB ordinary heap and
collections-catalog relations, the required tuple-content subset is:

| WAL record | Deterministic state transition |
|---|---|
| `XLOG_HEAP_INSERT` | Block 0 is the heap page. `xl_heap_insert.offnum` identifies the line pointer. Block data contains `xl_heap_header` followed by bytes beginning at `SizeofHeapTupleHeader`, unless an FPI satisfies the block reference and `XLH_INSERT_CONTAINS_NEW_TUPLE` is absent. `XLOG_HEAP_INIT_PAGE` establishes an empty page before insertion. |
| `XLOG_HEAP2_MULTI_INSERT` | Block 0 contains aligned `xl_multi_insert_tuple` entries. Non-init records take offsets from the main-data array; init-page records assign consecutive offsets beginning at `FirstOffsetNumber`. An FPI may be the only tuple source. |
| `XLOG_HEAP_UPDATE` / `XLOG_HEAP_HOT_UPDATE` | Block 0 is the new page; block 1 is the old page only when it differs. Without block 1, old and new are on the same page. `old_offnum` selects the base tuple and `new_offnum` the result. HOT updates must remain on one page. Prefix and suffix lengths are zero, one, or two leading `uint16` values in block 0 data, followed by `xl_heap_header` and the logged tuple fragment. |
| `XLOG_HEAP_DELETE` | `offnum` identifies the deleted tuple. The physical tuple remains addressable until later pruning; the semantic delete is emitted only on commit. Logged old tuple/key data can enrich output but does not replace physical-state validation. |
| `XLOG_HEAP_TRUNCATE` | This record exists primarily for logical decoding and names relation OIDs, not physical forks. Physical truncation is taken from the matching storage-manager truncate records and relation mapping; all cached blocks at or beyond the new fork length are removed. |

The tuple reconstruction algorithm follows PostgreSQL redo exactly:

1. Load the old tuple selected by the old relation generation, block, and
   `old_offnum`. Its line pointer must be normal and its tuple bytes must be
   trusted at the record's predecessor LSN.
2. Parse prefix length first when `XLH_UPDATE_PREFIX_FROM_OLD` is set, then
   suffix length when `XLH_UPDATE_SUFFIX_FROM_OLD` is set. Either flag on a
   moved-page update is invalid because PostgreSQL permits these deltas only
   when old and new blocks are the same.
3. Parse `xl_heap_header`. Its `t_hoff` defines the bitmap/padding area copied
   from WAL. Copy that area, then the requested prefix beginning at the old
   tuple's `t_hoff`, then the remaining logged data, then the suffix ending at
   the old tuple's physical length.
4. Check every addition and range before copying: header sizes, `t_hoff`,
   prefix and suffix bounds, maximum heap tuple size, line-pointer offset, and
   exact consumption of block data. Recreate the fixed heap header fields
   needed for physical tracking (`xmin`, `xmax`, `ctid`, infomasks, and
   command-ID placeholders) using the matching major's redo rules.
5. Store the result at `new_offnum`, update the old tuple's update-chain
   metadata, and then decode the reconstructed tuple descriptor, varlena
   alignment, object ID, and BSON document. Same-page processing must retain a
   copy of the old bytes before changing either line pointer.

An FPI is a post-record authoritative image for that block. The decoder removes
any hole according to the image header, validates page header and item
boundaries, and replaces the cached page generation with the image before
extracting the inserted or updated tuple. It does not apply the same block's
tuple delta a second time. On a moved-page update, each block reference is
handled independently: an image can authoritatively replace the old page, the
new page, both, or neither. A compressed image is accepted only through the
matching PostgreSQL-major decompressor and with exact restored size.

The heap insert/update/delete layouts needed here are stable across PostgreSQL
16, 17, and 18, but the surrounding heap2 redo surface is not. PostgreSQL 17
replaced the PostgreSQL 16 prune/vacuum/freeze split with reason-specific prune
records and combined prune/freeze subrecords; PostgreSQL 18 also changed
in-place-update metadata. Consequently the implementation has separate
major-specific dispatch and golden fixtures rather than a shared numeric
opcode parser. A record may be ignored only when the matching-major analysis
proves it cannot change tuple bytes, line-pointer identity, relation lifetime,
or a required mapping.

#### Physical state and relation lifetime

The disk-backed state is a sparse physical model, not an MVCC-visible table:

- cluster identity and timeline ancestry;
- relation generations keyed by tablespace, database, relfilenode, fork, and
  half-open LSN lifetime;
- relation-OID-to-relfilenode history where it is proved by catalog/manifest
  state;
- per-block page generation, latest applied record end LSN, page-header facts,
  line-pointer state, and complete raw tuple bytes;
- TOAST chunk state for supported values;
- committed DocumentDB namespace/descriptor state;
- open top-level/subtransaction staging and prepared-transaction state.

Physical heap redo is applied in WAL order regardless of eventual commit or
abort, just as PostgreSQL recovery applies it: an aborted tuple version can be
the physical base of later cleanup or reuse. DocumentDB events, catalog
namespace changes, and the logical current-row indexes are transaction-aware
and become committed state only at commit; abort discards those semantic
changes, not the already replayed physical page history.

Relation state starts only from proof, never from a familiar relfilenode:

- storage-manager create starts a new empty fork generation;
- init-page and valid FPIs can establish a page generation;
- storage-manager truncate removes blocks beyond the recorded fork size;
- commit/abort relfile lists close the appropriate generation at the outcome
  boundary;
- database/tablespace drop and relation rewrite close all affected mappings;
- relfilenode reuse always receives a new generation and cannot inherit tuples,
  TOAST chunks, names, or trust from the prior generation.

`XLOG_HEAP_TRUNCATE` is useful corroboration and logical relation identity, but
is not by itself evidence that an arbitrary cached relfilenode was truncated.
The decoder must join it to a trustworthy mapping and the physical
storage-manager records.

The first implementation supports main-fork ordinary DocumentDB document and
collections-catalog heaps, their required TOAST heaps/index identity, and the
above insert/multi-insert/update/HOT/delete/truncate transitions. Speculative
insert confirmation, heap locks, visibility changes, pruning, freezing,
vacuum, in-place updates, rewrites, storage-manager operations, and relevant
catalog records each need a matching-major classifier. The classifier either
applies a proven tuple/line-pointer/lifecycle transition, proves the record is
content-neutral for this cache, or invalidates the smallest safe scope. An
unknown or malformed redo record is never silently skipped.

#### Trust, mid-history input, and certainty

Trust is tracked independently for each relation generation and page:

- `origin-proved`: replay began at a proved cluster origin and remained
  contiguous;
- `image-proved`: a valid init-page record or FPI established this page and
  every subsequent relevant mutation is supported;
- `untrusted`: predecessor bytes are unknown or an unsupported/gapped mutation
  may have changed them.

Starting in the middle of retained history must not assume empty relations or
pages. Records can still be reported as physical facts, and complete tuple
images can produce local `after` documents, but prefix/suffix events depending
on untrusted predecessor state remain incomplete. A later authoritative FPI or
init-page can restore trust for that page; a relation create can restore trust
for a new generation. It cannot retroactively make earlier events complete.

An unsupported content-changing record invalidates its referenced page. An
unsupported relation rewrite, truncate, mapping transition, timeline
transition, or ambiguous storage operation invalidates the relation generation.
A WAL gap invalidates every state object whose intervening mutation cannot be
excluded; by default the cache as a whole becomes unusable beyond the last
safe checkpoint. No event after an unsafe boundary is promoted above
`incomplete` until trust is re-established.

Stable reconstruction warnings include
`update_base_page_untrusted`, `update_base_tid_missing`,
`update_base_line_pointer_not_normal`, `update_delta_malformed`,
`update_after_tuple_invalid`, `page_image_invalid`,
`physical_redo_unsupported`, `relation_generation_unknown`,
`toast_value_incomplete`, `wal_gap_after_checkpoint`, and
`timeline_history_unproved`.

#### Proving cluster origin and timeline continuity

“All WAL we retained” is not sufficient proof. Origin replay requires an
origin certificate generated at cluster initialization or independently
derivable from the archive, containing PostgreSQL major, system identifier,
WAL segment size, initial timeline, first record LSN, and the first segment's
cryptographic digest. The decoder verifies:

1. timeline 1 has no predecessor history file;
2. the first readable record is the certified initial record and has the
   PostgreSQL-defined no-predecessor `xl_prev` value;
3. page headers, record CRCs, record-end/previous-record links, segment
   sequence, and timeline history are continuous from that point;
4. the bootstrap checkpoint and subsequent relation/storage creation records
   occur in the verified stream; and
5. every later timeline switch has its complete `.history` ancestry and an
   exact fork point already applied.

Without those conditions the run is a mid-history run, even if the earliest
available filename looks like an initial segment. A manifest may bind known
relations and descriptors but cannot assert empty physical pages. A cache
built on timeline history A cannot be opened on divergent history B; the
operator rebuilds a separate cache from their common certified origin.

#### Cache format, checkpoint, and idempotence

The cache header and every atomic checkpoint record:

- cache format version and checksum algorithm;
- PostgreSQL major, system identifier, WAL segment size, block size, checksum
  setting, and initial timeline;
- complete timeline-history identities and file digests;
- exact DocumentDB extension/schema descriptor versions;
- origin-certificate digest and bootstrap method;
- replay-through record end LSN and last fully applied committed LSN;
- active/prepared transaction journal generation;
- ordered replay-ledger digests for the overlap window;
- relation/page/tuple/TOAST state root checksums;
- configured resource limits and creation/tool version.

`last fully applied committed LSN` is the greatest commit record whose complete
WAL prefix and semantic transition are durable. `replay-through LSN` may be
later because physical records from open transactions must also be durable.
The active transaction journal is checkpointed in the same atomic generation,
so restart does not reinterpret those effects as committed.

Updates are written to a new generation using a write-ahead cache journal,
checksummed records, `fsync` of data and containing directories, and an atomic
owner-only manifest switch. The previous complete generation is retained until
the switch is durable. On startup, torn journals, checksum failures, impossible
LSN ordering, or root mismatches select the previous generation or fail closed;
they are never repaired by guessing.

Replay accepts overlap. For every overlapping record, the decoder verifies its
start/end LSN, previous-record link, resource manager, record CRC/digest, and
record-result ledger entry; page/relation result checksums provide an additional
guard for touched state. An exact match is already applied and is not emitted
or staged a second time. A different record at the same LSN is divergence and
invalidates the candidate cache. New input must begin at or before the cache
replay point and cover a verified continuous path beyond it; beginning after
it is a gap.

#### Resource and privacy requirements

Because raw tuples and TOAST chunks contain customer documents, the cache is
backup-sensitive data. Its root directory must be a non-symlink owned by the
effective UID with mode 0700; regular files are 0600; lock, journal, replacement,
and debug files follow the same rule. The tool refuses group/world-readable
paths, never places cache data in a generic temporary directory, does not log
tuple bytes, and documents secure deletion limitations of copy-on-write and
flash storage.

RAM is bounded by explicit page-cache, transaction-journal, and decode-buffer
limits with deterministic LRU eviction of clean pages and spill of dirty state
to the cache journal. Disk is bounded by `--max-cache-bytes`; exceeding it
stops before advancing the checkpoint. The design does not evict arbitrary
tuple history needed for correctness. Space can be reclaimed only through
proved truncate/drop/prune transitions, completed checkpoint compaction, or a
full rebuild with a larger bound. Maximum tuple/document/TOAST sizes are
checked before allocation.

#### Absence, rebuild, replacement, and debugging

The cache is optional:

- with no `--cache`, a run replays from the certified cluster origin using
  bounded RAM and, when needed, a process-private state store under the
  explicitly supplied owner-only `--spill-dir`; without such a directory it
  fails at the RAM bound rather than writing elsewhere, and removes ephemeral
  state on clean exit;
- `--rebuild-cache` ignores but does not modify the existing cache, rebuilds a
  sibling candidate from full history, validates it through the requested end
  LSN, and atomically replaces the old cache only after success;
- `--ephemeral-cache <private-directory>` creates a named non-reusable debug
  store with page/tuple provenance and checksums but redacts document bytes
  from diagnostic rendering by default;
- `--cache-readonly` verifies and uses a cache without advancing it;
- cache deletion is always supported; the next ordinary or forced rebuild
  deterministically recreates it from the same certified WAL.

Rebuild progress is durable and includes the last verified record boundary,
candidate generation, source segment digests, state roots, and active
transaction journal. Interruption leaves the old cache active and the candidate
resumable. Resume first revalidates every source segment digest through the
saved boundary and then continues from an overlap window. `--restart-rebuild`
securely abandons the candidate metadata and starts again. Failed candidates
are never promoted, and successful replacement uses the same atomic manifest
switch as a normal checkpoint.

#### Staged implementation and certainty gates

1. **Record-conformance harness:** major-specific parsers for PostgreSQL 16,
   17, and 18, FPI restoration, page/item validation, relation generation, and
   byte-for-byte comparison with PostgreSQL redo outcomes. No semantic
   completeness claim.
2. **Ephemeral origin replay:** insert, multi-insert, update/HOT, delete, and
   physical truncate/relation lifecycle for ordinary non-TOASTed DocumentDB
   tuples. `after` becomes `certain` only for origin/image-proved pages.
3. **Persistent cache:** atomic generations, active transaction journal,
   overlap verification, deletion/rebuild/resume, privacy checks, and bounded
   resources.
4. **TOAST and maintenance coverage:** required TOAST lifecycle plus
   matching-major prune/freeze/vacuum/lock/visibility handling sufficient to
   preserve trust during multi-year real workloads.
5. **Catalog integration:** use the same physical state for collections rows,
   relation history, and committed namespace folding.

Stages 1-3 must not advertise multi-year completeness while a commonly emitted
maintenance record can invalidate needed page state. Unsupported redo remains
visible in output and metrics so field evidence determines the next coverage
gate.

### TOAST reconstruction

The decoder tracks TOAST inserts, updates, and deletes by transaction and value
ID. It reconstructs a BSON value only when all chunks are available from:

- trusted physical state rebuilt from contiguous WAL, including the cache;
- the supplied WAL range; or
- a matching read-only base page from `--pgdata`.

If chunks are missing, the event remains valid but the affected value is
`incomplete`. Strict mode exits non-zero at the first incomplete requested
document. Prefix/suffix reconstruction can prove the heap tuple while its
external value remains incomplete; because an update's resulting `after`
document is required, such an update is still incomplete until all referenced
TOAST chunks are proved. PostgreSQL's per-value size and chunk-count limits,
the configured document limit, chunk sequence, total reconstructed length, and
varlena compression method are validated before BSON decoding. Unsupported
compression or a value whose chunks predate a trustworthy origin/cache state
is never partially rendered.

### Collections catalog decoder and catalog-state cache

The ordinary tuple, transaction-folding, lifecycle classification, SQLite
catalog cache, full-page-image tuple seeding, and prefix/suffix reconstruction
described here are shipped. Origin certificates, checksummed cache generations,
full TOAST, and complete maintenance coverage remain future behavior.
It is based only on public `documentdb/documentdb` releases and PostgreSQL WAL
formats. Source findings were checked against every public tag from `v0.100-0`
through `v1.0-RC2`, specifically
`pg_documentdb/sql/schema/collection_metadata--0.10-0.sql`, its view and schema
validation additions, `documentdb--0.111-0--0.112-0.sql`, and the public create,
rename, and drop command implementations. A separate disposable, unmodified
public `documentdb-local` instances were used only to confirm physical WAL
behavior. Final implementation acceptance is pinned to public `v1.0-RC2` commit
`b0cb0dae85e8746f4e0b79c847894179b2f80d64`, multiarch image digest
`sha256:906670c630fc94e97b310a4951c5c0b81cb2853de4ccb21f75808031d4e2714d`
(PostgreSQL 17, verified extension `1.0-0`) and default
`wal_level=replica`. No private implementation or service is an input to this
design.

#### Supported catalog descriptors

Fresh installs and upgrade scripts produce these physical attribute orders:

| Public extension versions | `documentdb_api_catalog.collections` attributes in `attnum` order |
|---|---|
| `0.100-0` through `0.111-0` | `database_name text NOT NULL`, `collection_name text NOT NULL`, `collection_id bigint NOT NULL`, `shard_key bson NULL`, `collection_uuid uuid NULL`, `view_definition bson NULL`, `validator bson NULL`, `validation_level text NULL`, `validation_action text NULL` |
| `0.112-0`, `0.113-0`, `0.114-0`, `0.116-0`, `0.117-0`, and `1.0-0` as shipped by public tags `v1.0-RC1` and `v1.0-RC2` | The preceding nine attributes, then `options bson NULL` as attribute 10 |

The table has primary key `(database_name, collection_name)`, a unique
`collection_id`, and default replica identity (`relreplident='d'`). The base
five-column declaration and the view/schema-validation additions are unchanged
across the public `v0.100-0` through `v1.0-RC2` tags; the public
`0.111-0--0.112-0` upgrade appends `options`. There is no public `v0.115-0`
tag. The two public 1.0 release-candidate tags both declare extension version
`1.0-0` and have the same ten-attribute descriptor. Support is selected by the
exact extension version plus a canonical descriptor fingerprint containing
attribute number, name, type, typmod, length, alignment, storage, nullability,
and dropped-column status. Unknown versions, fingerprints, or attribute counts
are unsupported, not guessed.

The decoder parses PostgreSQL tuple headers, null bitmaps, alignment, text,
bigint, UUID, and enough DocumentDB `bson` varlena structure to distinguish a
view from a collection. External or compressed catalog BSON that cannot be
reconstructed is retained as unavailable internal state. Identity fields 1-3
must be complete before a named lifecycle event is emitted. `shard_key`,
validation fields, and `options` may be retained only as opaque raw tuple bytes
needed for later physical reconstruction; lifecycle output never exposes or
claims original command options.

#### WAL shapes and transaction folding

The public implementation performs these catalog mutations:

- create inserts a catalog row, often in an internal subtransaction, before
  creating `documentdb_data.documents_<collection_id>`;
- rename executes `UPDATE ... SET collection_name = ...` with stable database
  and collection ID;
- drop executes `DROP TABLE ... documents_<collection_id>` and then deletes the
  catalog row by collection ID;
- drop-database loops over drop-collection; there is no separate database row.

At PostgreSQL WAL level this means:

| Transition | Required WAL handling |
|---|---|
| Create | A heap insert into `documentdb_api_catalog.collections`, encoded as `XLOG_HEAP_INSERT` or, if PostgreSQL batches writes, `XLOG_HEAP2_MULTI_INSERT`. Tuple bytes are block data unless an FPI is the authoritative source. `XLOG_SMGR_CREATE` for `documents_<collection_id>` corroborates storage creation but does not name the collection. |
| Rename | `XLOG_HEAP_UPDATE` or `XLOG_HEAP_HOT_UPDATE` of the catalog row. Block 0 contains the new tuple or a prefix/suffix delta; `old_offnum` identifies the predecessor TID. At `wal_level=replica`, neither a complete old row nor a standalone complete new row is guaranteed. |
| Drop | `XLOG_HEAP_DELETE` of the catalog row after `DROP TABLE ... documents_<collection_id>`. With default replica identity and `wal_level=replica`, the delete normally carries relation/block/offset only. Commit relfile lists corroborate physical removal but do not recover the deleted namespace. |

The earlier disposable `0.117-0` check observed two catalog inserts for first collection
creation (the internal `system.dbSentinel` plus the user collection), a rename
update with prefix/suffix flags `0x60`, and a delete with flags `0x00`.
The same assumptions must be revalidated by automated acceptance against
`v1.0-RC2`; the decoder must not assume full tuples, logical decoding settings,
or one catalog row per client operation.

Catalog changes are staged by top-level transaction, including child
transactions, and folded to each row's net pre-commit and post-commit state.
Only committed net transitions update decoder state or emit lifecycle events.
This prevents a view created as an insert followed by a `view_definition`
update from being mislabeled as an ordinary collection, and prevents aborted
or intermediate names from escaping.

Classification rules are:

| Complete committed state transition | Event |
|---|---|
| absent to present, `view_definition` NULL | `collectionCreate` |
| absent to present, `view_definition` non-NULL | `viewCreate` |
| present to present, stable `collection_id` and `database_name`, changed `collection_name` | `collectionRename` or `viewRename` |
| present to absent | `collectionDrop` or `viewDrop` |
| present to present without a lifecycle change | no lifecycle event; later work may expose a generic metadata-change event |

`system.dbSentinel` is internal colocation metadata and is suppressed from
DocumentDB lifecycle output by default. A rename with `dropTarget=true` is
represented by a target drop and source rename in the same committed
transaction. Storage `CREATE` and commit-time relfile drops are corroborating
physical evidence only; they are not sufficient to recover a namespace.

#### Catalog cache state and provenance

**Current implementation boundary:** the shipped SQLite sidecar stores exact
catalog row tuples/TIDs, pending mutations, a replay ledger, mutable coverage,
and a replay/commit checkpoint. It validates owner-only permissions and exact
cluster/major/segment/timeline/version/descriptor provenance. Persistent,
atomic rebuild, memory-only, and disposable modes are implemented.
Crash-resumable rebuild journals, segment digests, state-root checksums,
timeline-history proofs, retained historical namespace intervals, and the
general physical page cache described below remain future hardening.

The catalog decoder is a committed semantic layer over the physical-state
cache defined above. Its durable state contains:

- cache schema version, checksum algorithm, and deterministic serialization
  version;
- PostgreSQL system identifier, exact major, block/WAL segment sizes, initial
  timeline, complete timeline-history digests, and origin-certificate digest;
- exact DocumentDB extension version and canonical collections-descriptor
  fingerprint for every half-open LSN interval in which it applies;
- relation OID, relfilenode, tablespace, database OID, fork, and generation
  history for the catalog and relevant document relations;
- committed rows indexed by collection ID, namespace, and physical heap TID,
  including raw tuple bytes and per-field availability;
- historical namespace intervals, relation-generation intervals, row-version
  provenance, and whether each database's pre-state is complete;
- replay-through record end LSN, last fully applied committed LSN, open and
  prepared transaction staging, replay-ledger hashes, and state-root checksum.

Each catalog mutation is staged with its top-level transaction and becomes
visible in one atomic cache generation with the commit record. Checkpoint
publication follows the journal, checksum, `fsync`, atomic manifest switch,
and previous-generation fallback rules above. A crash before publication
leaves the prior checkpoint active; a crash after publication exposes the
entire committed catalog transition, never a partial rename or drop.

Overlapping and duplicate ingestion is idempotent. Records at or before the
durable replay point are matched by LSN range, previous-record link, timeline,
record digest, transaction outcome, and resulting state hash. Exact duplicates
do not mutate state or re-emit events. A different record or result at the same
LSN is divergence and fails closed. Output is deterministic: committed events
are sorted by commit LSN, then top-level transaction ID, catalog record LSN,
collection ID, and operation ordinal; JSON keys and warning arrays have fixed
order.

The operation ordinal is fixed by schema: `databaseCreate` first, then target
`collectionDrop`/`viewDrop`, source `collectionRename`/`viewRename`, and finally
`collectionCreate`/`viewCreate`, each secondarily ordered by collection ID.
This ordering describes decoder output only and does not claim client command
order inside the transaction.

RAM uses the bounded physical page cache plus bounded namespace indexes. Catalog
row versions spill to the owner-only journal. Checkpoint compaction preserves
current rows and the historical intervals needed at or after the configured
overlap/retention floor, but may discard derived event JSON and obsolete
physical versions below that floor. An older query is then replayed
deterministically from retained source WAL rather than answered from guessed
cache state. The cache never promises a fixed byte ceiling smaller than its
live correctness state: if live rows, active transactions, or required overlap
history exceed `--max-cache-bytes`, it stops before advancing the checkpoint.
Dropped generations, superseded checkpoints, and event materializations can be
garbage-collected only after no retained checkpoint, overlap window, prepared
transaction, or requested historical interval references them.

The catalog cache inherits the physical cache's backup-sensitive classification:
0700 non-symlink directory, 0600 files, owner verification, no namespace or raw
tuple data in ordinary logs, and fail-closed behavior for bad permissions.
Checksums cover headers, journal frames, descriptor records, row blobs, interval
indexes, and the generation state root. Corruption, unsupported cache schema,
PostgreSQL-major mismatch, system-identifier mismatch, unproved or divergent
timeline, DocumentDB descriptor mismatch, a WAL gap, unsupported relevant redo,
or an impossible committed-LSN ordering invalidates use beyond the last proved
checkpoint.

Cache absence and deletion are normal:

- `--rebuild-cache` replays full certified WAL into a sibling candidate and
  atomically replaces the active cache only after end-to-end validation;
- an incompatible or corrupt cache is preserved for diagnosis, never modified
  in place, while a separately named candidate is rebuilt;
- `--no-persistent-cache` performs the same decode with bounded ephemeral state
  and leaves no reusable checkpoint;
- `--ephemeral-cache <private-directory>` retains an explicitly named
  disposable debug store with provenance, row/TID history, checksums, and
  redacted rendering;
- rebuild progress records verified segment digests, record boundary, state
  roots, active transactions, and candidate generation. Interruption is
  resumable after overlap revalidation, while the old cache remains active.

Deleting the cache cannot change semantic output. Given the same certified WAL,
decoder versions, limits, and output range, a clean rebuild must produce
byte-identical ordered JSONL. A forced rebuild is also the recovery path for
format upgrades; automatic migration of untrusted old bytes is not required.

#### Proving start of cluster and catalog completeness

A filename beginning at an apparently low segment number is not proof of an
empty cluster. Catalog completeness requires the cluster-origin proof defined
above and, additionally:

1. the verified timeline-1 stream starts at the certified first WAL record and
   remains contiguous through the requested end;
2. bootstrap database/catalog relation creation and every subsequent relation
   rewrite or relfilenode transition are decoded without an unsupported
   state-changing record;
3. creation of the `documentdb_api_catalog.collections` generation and its
   exact descriptor are observed before its first heap mutation; and
4. every catalog heap mutation from that point is physically reconstructed and
   assigned a known commit, abort, or prepared state.

Only then is cluster/catalog coverage `complete-from-origin`. Extension creation
may occur long after `initdb`; seeing the extension relation be created in a
continuous origin-proved stream is sufficient because that new relation
generation is proved empty. A manifest, extension version string, first observed
insert, FPI, or low LSN alone cannot establish complete catalog history.

#### Range-boundary state and mid-history input

The minimum state for a catalog relation is:

- exact extension descriptor and physical relation identity over a half-open
  LSN interval;
- committed rows keyed by `collection_id` and by heap TID
  `(relfilenode, block, offset)`;
- each row's decoded values and raw tuple payload, so a later prefix/suffix
  update can be reconstructed;
- whether user-visible row coverage for each database is complete;
- the last completely applied commit LSN.

A range beginning before a row's insert can build trustworthy state for that
row. A range beginning after existing rows were created cannot reliably name a
default-WAL rename or delete from a relation mapping alone. The implementation
therefore supports three honest modes:

1. replay from a proved cluster/catalog origin and obtain complete coverage;
2. resume from a validated tool-owned cache checkpoint with raw row/TID and
   coverage state; or
3. process mid-history input as partial evidence.

Version 2 manifests intentionally do not inject lifecycle rows. Until cache
bootstrap or read-only offline-page bootstrap is implemented, a mid-history
rename/drop is incomplete. A logical list of collections without raw tuple/TID
state is insufficient for prefix/suffix update reconstruction.

Mid-history mode never treats missing rows as an empty cluster. A committed
catalog insert with a complete tuple can establish that row and support an
inferred `collectionCreate` from that LSN forward. A complete update can
establish post-state, but `collectionRename` requires a trustworthy predecessor
name and stable collection ID. A delete requires trustworthy pre-state. Events
whose evidence is locally complete are emitted; dependent claims are emitted
as `unknown`/`incomplete` with coverage `partial`, not suppressed or promoted.
A later relation create, init-page, or FPI may restore trust for its exact
scope, but cannot retroactively complete earlier events.

#### Logical database inference

Public DocumentDB has no independent logical-database catalog row. Database
existence is represented by collections. The decoder emits `databaseCreate`
only when complete pre-transaction coverage proves zero user-visible
collection/view rows and the committed transaction establishes the first one.
`system.dbSentinel` is excluded from the count. The event is `inferred` logical
materialization, not evidence of a MongoDB `createDatabase` command.

With row-local boundary state, a transaction that inserts both
`system.dbSentinel` and the first user-visible row proves database materialization
within that transaction and can emit `databaseCreate`. Without that local
sentinel evidence or complete cached pre-state, no `databaseCreate` is emitted.
The scope does not
emit `databaseDrop`: deletion of the final row is observationally compatible
with `dropCollection`, `dropDatabase`, or other implementation paths, so it
cannot recover original intent.

#### Certainty, incomplete behavior, and event schema

Heap/storage records remain `physical`; exact tuple field values and commit
outcomes are `certain`; DocumentDB lifecycle meaning is `inferred`. A recognized
catalog mutation is `incomplete` when required relation mapping, tuple bytes,
base tuple/TID, descriptor, or range continuity is absent.

Incomplete input never produces a guessed named lifecycle operation. It emits
`eventType: "catalog"` and `operation: "unknown"` with the physical identity,
available collection ID/name fields, coverage (`complete-from-origin`,
`complete-from-cache`, `row-local`, or `partial`), and stable warning codes such as
`catalog_tuple_unavailable`, `catalog_update_base_missing`,
`catalog_delete_state_missing`, or `catalog_descriptor_unsupported`.
`--strict` fails if such an event is within the requested output range.

Complete lifecycle JSONL extends output schema version 1 additively:

```json
{
  "schemaVersion": 1,
  "certainty": "inferred",
  "eventType": "catalog",
  "operation": "collectionRename",
  "timestamp": "2026-10-09T22:30:37.329428Z",
  "timeline": 1,
  "transactionId": 756,
  "eventLsn": "0/234EE38",
  "commitLsn": "0/234EF20",
  "relation": {"tblspaceOid": 1663, "databaseOid": 5, "relfilenode": 18468},
  "database": "wal_design",
  "collection": "renamed",
  "collectionId": 6401,
  "objectKind": "collection",
  "coverage": "complete-from-cache",
  "before": {"database": "wal_design", "collection": "items"},
  "after": {"database": "wal_design", "collection": "renamed"},
  "evidence": ["collections_catalog_update"],
  "warnings": []
}
```

`before` and `after` here are catalog namespace summaries, never reconstructed
MongoDB command documents. Events contain no original command, user/client
identity, command aliases, field order, write concern, or creation options, and
do not claim whether creation was explicit, implicit through insert/upsert/index
creation, or part of another command. The provenance object identifies only
decoder evidence: catalog descriptor fingerprint, relation generation, source
record LSNs/digests, transaction outcome LSN, origin/cache coverage, and stable
warning codes.

### CLI

```bash
documentdb-wal-audit [OPTIONS] <WAL_SEGMENT...>
documentdb-wal-audit --wal-dir <DIRECTORY>
```

Input options:

```text
--wal-dir <path>
--manifest <path>
--pgdata <path>
--cache <path>
--cache-readonly
--rebuild-cache
--restart-rebuild
--no-persistent-cache
--ephemeral-cache <private-directory>
--max-cache-bytes <bytes>
--spill-dir <private-directory>
--documentdb-version <version>
```

Filters:

```text
--from-lsn <lsn>
--to-lsn <lsn>
--from-time <timestamp>
--to-time <timestamp>
--transaction <xid>
--collection-id <id>
--database <name>
--collection <name>
--operation insert|update|delete|ddl
--certainty physical|certain|inferred|incomplete
```

Output and safety:

```text
--format text|jsonl
--pretty
--redact-documents
--max-document-bytes <bytes>
--include-aborted
--show-postgres-records
--strict
--best-effort
--max-page-cache-bytes <bytes>
--max-transaction-bytes <bytes>
```

JSON Lines objects include:

```text
schemaVersion
certainty
eventType
operation
timestamp
timeline
transactionId
eventLsn
commitLsn
relation
database
collection
collectionId
objectId
coverage
before
after
provenance
warnings
```

### Compatibility

The native decoder is built once per PostgreSQL major, defaulting to
18 with matching builds for 16 and 17. A PostgreSQL 17 native binary must not
read PostgreSQL 18 WAL, or vice versa. At startup the complete design validates:

- PostgreSQL major version;
- WAL segment size;
- system identifier when available;
- timeline sequence;
- DocumentDB schema descriptor version;
- BSON storage compatibility.

Unknown PostgreSQL record versions are fatal unless `--show-postgres-records`
can safely render them as opaque physical records.

### Gaps and corruption

The CLI distinguishes:

- expected end of input;
- missing WAL segment;
- invalid checksum;
- timeline gap;
- incomplete transaction;
- missing relation mapping;
- cache/WAL continuity mismatch;
- cache checksum or version mismatch;
- missing old tuple;
- missing TOAST chunks;
- unsupported tuple descriptor.

Default mode emits complete transactions up to the first unsafe gap and exits
non-zero. `--best-effort` may continue only after emitting a prominent gap
event in text and JSONL. It must not advance or promote a persistent cache
across a gap, unsupported state-changing record, unproved timeline fork, or
relation-generation ambiguity.

### Security

WAL and offline data directories can contain current and deleted customer
documents. They must be handled like backups.

- input is opened read-only;
- no network listener or database connection is created;
- runtime containers should disable networking, use a read-only root filesystem,
  drop capabilities, and prevent privilege escalation;
- output defaults to stdout;
- temporary spill files use owner-only permissions;
- physical-state caches use owner-only directories and files because they
  contain current and deleted document tuples and TOAST chunks;
- document values are excluded from diagnostic logs;
- `--redact-documents` preserves metadata while suppressing BSON bodies;
- malformed WAL and BSON are treated as untrusted input.

### Testing strategy

Generate fixtures from unmodified DocumentDB instances for each supported
PostgreSQL major:

- insert, update, replacement, upsert, and delete;
- update-many and delete-many;
- TTL delete;
- committed and aborted transactions;
- subtransactions and prepared transactions;
- interleaved transactions;
- toasted maximum-size documents;
- WAL ranges beginning before and after required TOAST chunks;
- collection create, rename, and drop metadata changes;
- index create and drop metadata changes;
- missing segments, corruption, and timeline changes;
- relation rewrites and relfilenode reuse.

The update-reconstruction target adds a mandatory PostgreSQL-major matrix.
Every case runs independently on 16, 17, and 18 with a binary built from the
matching headers:

- compare reconstructed page slots and tuple bytes after every supported record
  with pages produced by native PostgreSQL crash recovery from the same WAL;
- insert and multi-insert with ordinary block data, init-page, uncompressed
  FPI, supported compressed FPI, FPI-only tuple data, nonconsecutive offsets,
  null bitmaps, short/4-byte varlena headers, and every alignment boundary;
- update and HOT update with no delta, prefix-only, suffix-only, both deltas,
  zero-length flagged deltas, same-page and moved-page records, all combinations
  of old-key/old-tuple/new-tuple flags, and old/new/both/no FPI;
- corrupted lengths, `t_hoff`, line pointers, page holes, image compression,
  prefix/suffix bounds, trailing bytes, moved-page delta flags, and HOT
  cross-page attempts, all of which must fail closed;
- delete followed by HOT/prune/offset reuse, storage create/truncate/drop,
  relation rewrite, relfilenode reuse, and records for forks or relations
  outside the DocumentDB subset;
- ordinary inline BSON and every supported TOAST size boundary, missing,
  duplicated, reordered, deleted, compressed, and oversized chunks; a complete
  update must always include its validated `after` document;
- full-origin replay, deliberately mid-history replay, page trust gained from a
  later FPI, gap before/after a base tuple, unsupported redo invalidation, and
  timeline fork/divergence with complete, missing, and altered history files;
- cache create/open/read-only/delete, exact-overlap replay, divergent overlap,
  format/checksum/descriptor mismatch, disk-full and RAM-limit behavior,
  owner/mode/symlink rejection, and deterministic rebuild without a cache;
- crash injection before and after every journal write, file sync, directory
  sync, checkpoint manifest switch, compaction, and replacement step, proving
  that startup selects either the old or new complete generation;
- forced rebuild interruption and resume at records with no transaction, open
  top-level and child transactions, prepared transactions, commit, and abort;
  resumed output and final state must equal an uninterrupted clean rebuild
  byte-for-byte apart from nondeterministic creation timestamps.

Real-workload gates run the public DocumentDB test suites and multi-day
insert/update/upsert/delete/TTL/view/catalog workloads on each PostgreSQL major,
with frequent checkpoints, forced FPIs, vacuum/pruning, large TOASTed documents,
timeline promotion, cache deletion, and rebuild from the retained origin WAL.
The oracle is Mongo read-back plus PostgreSQL-recovered physical pages and
committed catalog state. A release cannot claim complete update reconstruction
for a major until no emitted record in that workload falls into an unsupported
state-changing class and every committed update has the expected `after`
document.

The collections-catalog target adds a focused public-release matrix:

- descriptor unit fixtures for the nine-attribute `0.100-0`/`0.111-0`
  boundary and ten-attribute `0.112-0`/`0.117-0` boundary, including every
  nullable bitmap and varlena-alignment transition; include public `1.0-0`
  from both `v1.0-RC1` and `v1.0-RC2`, and reject a known version paired with
  a changed descriptor fingerprint;
- container fixtures using exact public release images where available, with
  PostgreSQL-major-matched audit binaries;
- default `wal_level=replica` create, explicit create, implicit create through
  insert/upsert/index creation, view create, rename, rename with
  `dropTarget=true`, drop, and drop-database;
- the same lifecycle transitions with `wal_level=logical`, proving that extra
  tuple images improve completeness without changing event classification;
- first-database creation with `system.dbSentinel`, verifying that internal
  metadata is suppressed and does not create a false user collection event;
- committed, aborted, subtransaction, interleaved, and prepared transaction
  variants, verifying transaction folding and commit-LSN ordering;
- ranges beginning before create, immediately before rename, and immediately
  before drop, both with and without a valid cache checkpoint;
- certified cluster-origin replay versus a low-numbered but uncertified first
  segment, missing bootstrap WAL, extension creation after `initdb`, catalog
  rewrite, and timeline fork with complete, missing, and divergent history;
- rename prefix-only, suffix-only, prefix-and-suffix, full-tuple, full-page
  image, cross-page update, and missing-base cases;
- delete with no old row, old key, full old row, stale TID, and relfilenode
  reuse;
- complete versus partial per-database coverage for `databaseCreate`, proving
  that `system.dbSentinel` is excluded and that no `databaseCreate` or
  `databaseDrop` is emitted from mid-history or final-row deletion;
- corruption, unsupported descriptor, catalog TOAST, WAL gaps, and cache
  continuity failures.

The persistent catalog-cache matrix additionally proves:

- clean replay, periodic checkpoint, process termination before and after each
  durability boundary, torn journal tail, corrupt current generation, valid
  previous-generation fallback, and impossible committed-LSN ordering;
- exact overlap, duplicate segment, duplicate transaction, partial overlap,
  overlap with one changed byte, gap after checkpoint, and divergent timeline;
- cache deletion followed by deterministic full rebuild, explicit forced
  rebuild, incompatible-format replacement, corrupt-cache replacement,
  interrupted candidate resume, and `--restart-rebuild`;
- byte-identical ordered JSONL for cached, rebuilt, and
  `--no-persistent-cache` runs over the same range;
- bounded RAM spilling, deterministic clean-page eviction, checkpoint
  compaction, legal historical GC, an old query that triggers replay from
  source WAL, disk-limit stop without checkpoint advance, and live state larger
  than the configured cap;
- owner, mode, symlink, and replacement-path attacks; checksums for headers,
  frames, row blobs, interval indexes, and state roots; and verification that
  ordinary logs/debug rendering do not expose names, BSON, raw tuples, users,
  commands, or options.

Expected lifecycle output is derived after capture from the committed public
catalog state and client workload, never supplied to the decoder as manifest
observations. Tests assert both positive events and forbidden claims: no event
for aborts, no claimed original `createDatabase`/`dropDatabase` command, no
command body, user/client identity, or options, no name guessed at an incomplete
boundary, and no promotion above `inferred`.

Each fixture records:

- client operation;
- expected physical records;
- expected guaranteed output;
- permitted inferred output;
- expected incompleteness warnings.

Fuzz WAL record boundaries, tuple headers, varlena lengths, BSON payloads,
TOAST chunk sets, manifests, and JSONL rendering.

### Complete-design acceptance criteria

The expanded implementation must demonstrate:

- correct commit and abort handling;
- no semantic output for aborted transactions unless requested;
- DocumentDB table recognition from a manifest;
- BSON decoding for ordinary inserts;
- explicit incomplete output for deletes without old tuples;
- maximum-size TOAST reconstruction when all chunks are present;
- bounded memory with spill for large transactions;
- deterministic text and JSONL output;
- explicit failure on missing required WAL;
- deterministic update `after` reconstruction from prefix/suffix WAL and
  trusted physical state on PostgreSQL 16, 17, and 18;
- cache deletion followed by a deterministic full-history rebuild;
- crash-safe, transaction-aware cache checkpoint and interrupted rebuild
  resume without semantic duplication;
- no reads or writes outside explicitly supplied paths.

### Optional future enhanced mode

A future version may define an optional DocumentDB audit-message format to
provide principals, command intent, and guaranteed images. That enhancement
would require database changes and is explicitly outside the version 1
design. The standalone physical decoder remains useful without it.

## Implementation Roadmap

### Stage 1: native core

1. Build C with matching pinned, checksum-verified PostgreSQL frontend source
   support and libbson, entirely inside Linux containers.
2. Default to PostgreSQL 18 and compile separate binaries for 16 and 17.
   Reject mismatched major-specific WAL page formats.
3. Use `XLogReader` to validate WAL pages, continuation fragments, CRCs, record
   ordering, and previous-record links before interpreting physical heap effects.
4. Track transaction outcomes without attributing committed semantics to
   aborted or unresolved effects.
5. Accept optional, cluster-, timeline-, major-, and LSN-scoped manifests for
   namespace recognition; decode ordinary BSON only for verified tuple layouts.
6. Provide JSON/text output, LSN filtering, document redaction, and errors for
   invalid, incomplete, or unsupported input.
7. Stream WAL, bound record/document sizes and aggregate retained event
   buffering, and spool pending transaction effects to a private writable
   directory when needed.
8. Verify implemented CLI flags, output schema, and decoder coverage before
   documenting them as available. Python is test-only; runtime needs neither
   a Python interpreter nor a running PostgreSQL server.

### Later stages: complete design

1. Expand the major-specific record-conformance harness and physical replay
   coverage for pruning, rewrites, and every gap source.
2. Add checksummed cache generations, explicit cache byte limits, readonly
   operation, and stronger origin certification.
3. Add full TOAST and maintenance-record coverage required to keep physical
   state trustworthy across multi-year DocumentDB workloads.
4. Interpret DocumentDB collection/index metadata and catalog transitions from
   the same transaction-aware state.
5. Add read-only offline data-directory bootstrap as an optional independent
   trust source and complete the remaining filters and safety modes.

Later stages are proposals, not completed release milestones. Ordinary
manifest-based BSON decoding must not be advertised as full document recovery,
TOAST reconstruction, or catalog inference.

## License

The project's own code is licensed under the MIT License. See [LICENSE](LICENSE).
PostgreSQL-derived source and support libraries retain the PostgreSQL License;
libbson retains its Apache License 2.0 terms. Those dependency licenses are
separate from the project's MIT License and must be retained when distributing
source or container artifacts.
