#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

runtime="${CONTAINER_RUNTIME:-}"
if [[ -z "$runtime" ]]; then
    if command -v podman >/dev/null; then runtime=podman;
    elif command -v docker >/dev/null; then runtime=docker;
    else echo "Install or start Docker or Podman first." >&2; exit 2; fi
fi
command -v "$runtime" >/dev/null
"$runtime" info >/dev/null
umask 077

# Multi-platform image published from public tag v1.0-RC2:
# https://github.com/documentdb/documentdb/tree/v1.0-RC2
image="${DOCUMENTDB_IMAGE:-ghcr.io/documentdb/documentdb/documentdb-local@sha256:906670c630fc94e97b310a4951c5c0b81cb2853de4ccb21f75808031d4e2714d}"
expected_documentdb_version="${EXPECTED_DOCUMENTDB_VERSION:-1.0-0}"
shell_image="${MONGOSH_IMAGE:-docker.io/library/mongo:8.0}"
jq_image="${JQ_IMAGE:-ghcr.io/jqlang/jq:1.8.1}"
audit_image="documentdb-wal-audit-demo:pg17"
name="wal-audit-demo-$(date +%s)-$$-$RANDOM"
mkdir -p demo-output
output="$PWD/demo-output/$name"
mkdir -m 700 "$output" "$output/wal" "$output/spill" "$output/cache"
network_created=false
volume_created=false

cleanup() {
    for container in "$name" "$name-shell" "$name-audit" "$name-jq"; do
        owner="$("$runtime" inspect "$container" \
            --format '{{index .Config.Labels "org.documentdb.wal-audit.demo"}}' 2>/dev/null || true)"
        if [[ "$owner" == "$name" ]]; then
            "$runtime" rm -f "$container" >/dev/null ||
                echo "Warning: could not remove demo container $container" >&2
        fi
    done
    if $volume_created; then
        "$runtime" volume rm "$name-data" >/dev/null ||
            echo "Warning: could not remove demo volume $name-data" >&2
    fi
    if $network_created; then
        "$runtime" network rm "$name-network" >/dev/null ||
            echo "Warning: could not remove demo network $name-network" >&2
    fi
}
trap cleanup EXIT
trap 'echo "Demo failed at line $LINENO; artifacts: $output" >&2' ERR
trap 'exit 130' INT
trap 'exit 143' TERM

echo "1. Pull DocumentDB, mongosh, and jq; build the PostgreSQL 17 audit image."
"$runtime" pull -q "$image" >/dev/null
"$runtime" pull -q "$shell_image" >/dev/null
"$runtime" pull -q "$jq_image" >/dev/null
"$runtime" build -q --build-arg PG_MAJOR=17 -t "$audit_image" . > "$output/build.log" 2>&1

shell_offline() {
    "$runtime" run --rm --name "$name-shell" --network none --read-only \
        --label "org.documentdb.wal-audit.demo=$name" \
        --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
        --tmpfs /tmp:rw,mode=1777 -e HOME=/tmp -e "DEMO_PHASE=$1" \
        -v "$PWD/scripts/demo.js:/demo.js:ro" -v "$output:/artifacts:rw" \
        --entrypoint mongosh "$shell_image" --nodb --quiet --file /demo.js
}
password="$(shell_offline credentials)"
[[ "$password" =~ ^[0-9a-f]{48}$ ]]
"$runtime" network create --internal "$name-network" >/dev/null
network_created=true
"$runtime" volume create "$name-data" >/dev/null
volume_created=true

echo "2. Start a separate disposable DocumentDB instance (no published ports)."
"$runtime" run -d --name "$name" --network "$name-network" --network-alias documentdb \
    --label "org.documentdb.wal-audit.demo=$name" \
    -v "$name-data:/data" -e TMPDIR=/home/documentdb \
    -e ENABLE_TELEMETRY=false -e DOCUMENTDB_USAGE_TELEMETRY=false \
    "$image" --username wal_demo_user --password "$password" >/dev/null
sql() {
    # Use PostgreSQL's local socket inside the demo container, not a host client.
    "$runtime" exec "$name" psql -X -v ON_ERROR_STOP=1 \
        -p 9712 -U documentdb -d postgres -Atqc "$1"
}
ready=false
# SELECT 1 checks that PostgreSQL accepts connections before inspecting metadata.
for ((i=0; i<90; i++)); do
    if sql 'SELECT 1' >/dev/null 2>&1; then ready=true; break; fi
    sleep 2
done
if [[ "$ready" != true ]]; then echo "DocumentDB PostgreSQL did not become ready." >&2; exit 1; fi
# server_version_num / 10000 extracts the major needed by the native WAL reader.
major="$(sql "SELECT current_setting('server_version_num')::int / 10000")"
if [[ "$major" != 17 ]]; then echo "This demo requires a PostgreSQL 17 DocumentDB image, got $major." >&2; exit 1; fi
documentdb_version="$(sql "SELECT extversion FROM pg_extension WHERE extname='documentdb'")"
if [[ "$documentdb_version" != "$expected_documentdb_version" ]]; then
    echo "Expected DocumentDB $expected_documentdb_version from v1.0-RC2, got $documentdb_version." >&2
    exit 1
fi
# Print server/extension versions and the unchanged WAL setting for provenance.
sql "SELECT json_build_object('postgres',current_setting('server_version'),'documentdb',(SELECT extversion FROM pg_extension WHERE extname='documentdb'),'walLevel',current_setting('wal_level'))"

shell_connected() {
    "$runtime" run --rm --name "$name-shell" --network "$name-network" --read-only \
        --label "org.documentdb.wal-audit.demo=$name" \
        --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
        --tmpfs /tmp:rw,mode=1777 -e HOME=/tmp -e "DEMO_PHASE=$1" \
        -v "$PWD/scripts/demo.js:/demo.js:ro" -v "$output:/artifacts:rw" \
        --entrypoint mongosh "$shell_image" \
        'mongodb://documentdb:10260/?tls=true&tlsAllowInvalidCertificates=true&retryWrites=false&serverSelectionTimeoutMS=3000' \
        --username wal_demo_user --password "$password" --authenticationDatabase admin \
        --quiet --file /demo.js
}
ready=false
for ((i=0; i<60; i++)); do
    if shell_connected ping > "$output/readiness.log" 2>&1; then ready=true; break; fi
    if grep -qiE 'AuthenticationFailed|Authentication failed|bad auth' "$output/readiness.log"; then
        echo "Mongo authentication failed." >&2; exit 1
    fi
    sleep 2
done
if [[ "$ready" != true ]]; then echo "Mongo gateway did not become ready; see $output/readiness.log." >&2; exit 1; fi

# Rotate away from initialization WAL so capture starts in a fresh segment.
# This changes only the disposable demo's WAL position, not its WAL settings.
sql 'SELECT pg_switch_wal()' >/dev/null
# Save the inclusive capture start before Mongo creates the database/collection.
start="$(sql 'SELECT pg_current_wal_insert_lsn()')"
echo "3. mongosh: create collection documents; database wal_audit_demo is created implicitly."
shell_connected setup
# Record the exclusive end of creation so verification can isolate its WAL.
setup_end="$(sql 'SELECT pg_current_wal_insert_lsn()')"
printf '%s %s\n' "$start" "$setup_end" > "$output/setup.range"
# Resolve physical catalog files to recognize their block references in WAL.
# A zero reltablespace means the database's default tablespace. These identifiers
# identify physical catalog writes; they do not decode semantic DDL commands.
sql "SELECT json_agg(json_build_object(
    'tblspaceOid',COALESCE(NULLIF(c.reltablespace,0),d.dattablespace)::bigint,
    'databaseOid',d.oid::bigint,'relfilenode',pg_relation_filenode(c.oid)::bigint))
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_database d ON d.datname=current_database()
    WHERE n.nspname IN ('pg_catalog','documentdb_api_catalog') AND c.relkind='r'" > "$output/catalog-relations.json"
# Export mappings for the collections catalog and document table.
# pg_control_system supplies the cluster ID; pg_control_checkpoint the timeline;
# pg_extension the DocumentDB version. pg_class supplies the physical file number.
# databaseOid identifies PostgreSQL's database, while collections.database_name
# identifies the logical Mongo database. The actual end LSN is filled in later.
sql "SELECT json_build_object(
    'schemaVersion',2,'postgresMajor',17,
    'systemIdentifier',(SELECT system_identifier::text FROM pg_control_system()),
    'timeline',(SELECT timeline_id FROM pg_control_checkpoint()),
    'documentdbVersion',(SELECT extversion FROM pg_extension WHERE extname='documentdb'),
    'validFromLsn','$start','validToLsn','FFFFFFFF/FFFFFFFF',
    'relations',(SELECT json_agg(r.entry) FROM (
        SELECT 0 AS ordering,json_build_object(
            'kind','collections_catalog',
            'tblspaceOid',COALESCE(NULLIF(c.reltablespace,0),d.dattablespace)::bigint,
            'databaseOid',d.oid::bigint,
            'relfilenode',pg_relation_filenode(c.oid)::bigint) AS entry
        FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_database d ON d.datname=current_database()
        WHERE n.nspname='documentdb_api_catalog' AND c.relname='collections'
        UNION ALL
        SELECT 1,json_build_object(
            'kind','document',
            'tblspaceOid',COALESCE(NULLIF(c.reltablespace,0),d.dattablespace)::bigint,
            'databaseOid',d.oid::bigint,'relfilenode',pg_relation_filenode(c.oid)::bigint,
            'collectionId',m.collection_id,'database',m.database_name,
            'collection',m.collection_name)
        FROM documentdb_api_catalog.collections m
        JOIN pg_class c ON c.oid=to_regclass('documentdb_data.documents_' || m.collection_id)
        JOIN pg_database d ON d.datname=current_database()
        WHERE m.database_name='wal_audit_demo' AND m.collection_name='documents'
        ORDER BY ordering) r))" > "$output/manifest.json"

echo "4. mongosh: insert three documents, update, replace, delete, create/drop an index."
shell_connected workload
echo "Mongo read-back (jq, canonical Extended JSON):"
"$runtime" run --rm --name "$name-jq" --network none --read-only \
    --label "org.documentdb.wal-audit.demo=$name" \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    -v "$output:/artifacts:ro" "$jq_image" . /artifacts/mongo-state.json
# End the capture after acknowledged Mongo writes; the range is [start, end).
end="$(sql 'SELECT pg_current_wal_insert_lsn()')"
printf '%s %s\n' "$start" "$end" > "$output/range"
# Read the configured file size so extraction rejects truncated WAL copies.
sql "SELECT pg_size_bytes(current_setting('wal_segment_size'))" > "$output/segment-size"
# Translate LSNs to segment names. end - 1 selects the last included byte,
# avoiding an extra segment when the exclusive end falls on a file boundary.
first="$(sql "SELECT pg_walfile_name('$start'::pg_lsn)")"
last="$(sql "SELECT pg_walfile_name('$end'::pg_lsn - 1)")"

echo "5. Close WAL segments and copy them into an immutable host archive."
# Force the workload's last segment to close and flush before copying its bytes.
sql 'SELECT pg_switch_wal()' >/dev/null
# Enumerate only canonical segment filenames covering the captured LSN range,
# excluding future preallocated files and archive-status files.
sql "SELECT name FROM pg_ls_waldir() WHERE name ~ '^[0-9A-F]{24}$' AND name >= '$first' AND name <= '$last' ORDER BY name" > "$output/segments"
[[ -s "$output/segments" ]]
while read -r segment; do
    [[ "$segment" =~ ^[0-9A-F]{24}$ ]]
    # Read closed WAL through PostgreSQL, transport it as hex via COPY TO STDOUT,
    # then restore binary files in the extract phase; never mount live PGDATA.
    "$runtime" exec "$name" psql -X -v ON_ERROR_STOP=1 -p 9712 -U documentdb -d postgres \
        -c "COPY (SELECT encode(pg_read_binary_file('pg_wal/$segment'),'hex')) TO STDOUT" \
        > "$output/wal/$segment.hex"
done < "$output/segments"
shell_offline extract

echo "6. Run the native audit container against the read-only WAL archive."
"$runtime" run --rm --name "$name-audit" --network none --read-only \
    --label "org.documentdb.wal-audit.demo=$name" \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    -v "$output:/capture:ro" -v "$output/spill:/spill:rw" \
    -v "$output/cache:/cache:rw" "$audit_image" \
    --wal-dir /capture/wal --manifest /capture/manifest.json --spill-dir /spill \
    --ephemeral-cache /cache \
    --from-lsn "$start" --to-lsn "$end" --format jsonl --show-postgres-records \
    > "$output/audit.jsonl"
shell_offline verify
echo
echo "Decoded WAL catalog lifecycle events (jq):"
"$runtime" run --rm --name "$name-jq" --network none --read-only \
    --label "org.documentdb.wal-audit.demo=$name" \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    -v "$output:/artifacts:ro" "$jq_image" . /artifacts/setup-lifecycle.json
echo
echo "Decoded WAL document effects (jq):"
"$runtime" run --rm --name "$name-jq" --network none --read-only \
    --label "org.documentdb.wal-audit.demo=$name" \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    -v "$output:/artifacts:ro" "$jq_image" -s \
    'map(select(.eventType == "document"))' /artifacts/audit.jsonl
echo
echo "Verification summary (jq):"
"$runtime" run --rm --name "$name-jq" --network none --read-only \
    --label "org.documentdb.wal-audit.demo=$name" \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    -v "$output:/artifacts:ro" "$jq_image" . /artifacts/verification.json
printf '\nSaved WAL, manifest, expected values, and audit.jsonl in:\n%s\n' "$output"
echo "Demo resources are cleaned up on exit; images and output are retained."
