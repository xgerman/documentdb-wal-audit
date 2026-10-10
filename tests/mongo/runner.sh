#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
runtime="${CONTAINER_RUNTIME:-podman}"
mode="${MONGO_WAL_MODE:-both}"
if [[ "$mode" == both ]]; then
    MONGO_WAL_MODE=default bash tests/mongo/runner.sh
    MONGO_WAL_MODE=precision bash tests/mongo/runner.sh
    exit
fi
[[ "$mode" == precision || "$mode" == default ]] || { echo "MONGO_WAL_MODE must be both, precision, or default" >&2; exit 2; }
# Multi-platform image published from public tag v1.0-RC2.
image="${DOCUMENTDB_IMAGE:-ghcr.io/documentdb/documentdb/documentdb-local@sha256:906670c630fc94e97b310a4951c5c0b81cb2853de4ccb21f75808031d4e2714d}"
expected_documentdb_version="${EXPECTED_DOCUMENTDB_VERSION:-1.0-0}"
suffix="$(date +%s)-$$-${RANDOM}-$mode"
name="wal-audit-mongo-${suffix}"
artifacts="$PWD/tests/mongo/artifacts/$suffix"
mkdir -p "$artifacts/wal"
chmod 700 "$artifacts" "$artifacts/wal"
cleanup() {
    "$runtime" rm -f "$name" "$name-driver" "$name-audit" >/dev/null 2>&1 || true
    "$runtime" volume rm "$name-data" >/dev/null 2>&1 || true
    "$runtime" network rm "$name-network" >/dev/null 2>&1 || true
    "$runtime" image rm "$name-driver-image" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'echo "FAIL: Mongo integration at line $LINENO (phase ${phase:-startup}); artifacts: $artifacts" >&2' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
"$runtime" pull -q "$image" >/dev/null
"$runtime" build -q -t "$name-driver-image" -f tests/mongo/Dockerfile . >/dev/null
"$runtime" network create --internal "$name-network" >/dev/null
"$runtime" volume create "$name-data" >/dev/null
export MONGO_USERNAME="audit_fixture"
export MONGO_PASSWORD
MONGO_PASSWORD="$(openssl rand -hex 24)"
"$runtime" run -d --name "$name" --network "$name-network" --network-alias documentdb \
    -v "$name-data:/data" -e TMPDIR=/home/documentdb \
    -e ENABLE_TELEMETRY=false -e DOCUMENTDB_USAGE_TELEMETRY=false \
    "$image" --username "$MONGO_USERNAME" --password "$MONGO_PASSWORD" >/dev/null
sql() {
    "$runtime" exec "$name" psql -X -v ON_ERROR_STOP=1 -p 9712 -U documentdb -d postgres -Atqc "$1"
}
ready=false
for ((i=0; i<120; i++)); do
    if sql 'SELECT 1' >/dev/null 2>&1; then ready=true; break; fi
    sleep 2
done
if [[ "$ready" != true ]]; then echo "BLOCKED: public PostgreSQL server did not start" >&2; exit 1; fi
major="$(sql "SELECT current_setting('server_version_num')::int / 10000")"
documentdb_version="$(sql "SELECT extversion FROM pg_extension WHERE extname='documentdb'")"
if [[ "$documentdb_version" != "$expected_documentdb_version" ]]; then
    echo "BLOCKED: expected DocumentDB $expected_documentdb_version from v1.0-RC2, got $documentdb_version" >&2
    exit 1
fi
toolchain="${AUDIT_TOOLCHAIN_IMAGE:-localhost/documentdb-wal-audit-toolchain:pg${major}}"
binary="build/pg${major}/documentdb-wal-audit"
if [[ ! -f "$binary" ]]; then
    echo "BLOCKED: need Linux binary $binary matching public image PostgreSQL $major" >&2; exit 1
fi
"$runtime" image exists "$toolchain" || { echo "BLOCKED: missing $toolchain" >&2; exit 1; }
sql "SELECT json_build_object('wal_level',current_setting('wal_level'),'full_page_writes',current_setting('full_page_writes'),'checkpoint_timeout',current_setting('checkpoint_timeout'))" > "$artifacts/server-defaults.json"
if [[ "$mode" == precision ]]; then
    sql "ALTER SYSTEM SET wal_level='logical'"
    sql "ALTER SYSTEM SET checkpoint_timeout='1h'"
    sql "ALTER SYSTEM SET max_wal_size='2GB'"
    "$runtime" exec "$name" pg_ctl restart -D /data -m fast -l /data/pglog.log >/dev/null
    [[ "$(sql 'SHOW wal_level')" == logical ]]
fi
printf '%s\n' "$mode" > "$artifacts/mode.txt"
sql "SELECT json_build_object('postgresMajor',$major,'systemIdentifier',system_identifier::text,'timeline',(SELECT timeline_id FROM pg_control_checkpoint()),'documentdbVersion',(SELECT extversion FROM pg_extension WHERE extname='documentdb')) FROM pg_control_system()" > "$artifacts/provenance.json"
sql "SELECT json_agg(json_build_object('tblspaceOid',COALESCE(NULLIF(c.reltablespace,0),d.dattablespace)::bigint,'databaseOid',d.oid::bigint,'relfilenode',pg_relation_filenode(c.oid)::bigint)) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_database d ON d.datname=current_database() WHERE n.nspname IN ('pg_catalog','documentdb_api_catalog') AND c.relkind='r'" > "$artifacts/catalog-relations.json"
"$runtime" image inspect "$image" --format '{{.Digest}}' > "$artifacts/image-digest.txt"
driver() {
    "$runtime" run --rm --name "$name-driver" --network "$name-network" \
        -e MONGO_USERNAME -e MONGO_PASSWORD -v "$artifacts:/artifacts:rw" \
        "$name-driver-image" "$1"
}
declare_start=""
# Begin our capture in a fresh segment, not an image's initialization continuation.
sql 'SELECT pg_switch_wal()' >/dev/null
for phase in create original rename renamed drop; do
    if [[ "$phase" == original || "$phase" == renamed ]]; then
        # Test-only physical fixture: force available ordinary old BSON images.
        relation="$(sql "SELECT 'documentdb_data.documents_' || collection_id FROM documentdb_api_catalog.collections WHERE database_name='wal_audit_mongo' AND collection_name IN ('items','renamed')")"
        if [[ ! "$relation" =~ ^documentdb_data.documents_[0-9]+$ ]]; then
            echo "Unexpected fixture collection relations: $relation" >&2
            sql "SELECT row_to_json(m) FROM documentdb_api_catalog.collections m" >&2
            exit 1
        fi
        sql "SELECT json_build_object('relation','$relation','replicaIdentity',relreplident) FROM pg_class WHERE oid='$relation'::regclass" > "$artifacts/$phase.relation-defaults.json"
        if [[ "$mode" == precision ]]; then sql "ALTER TABLE $relation REPLICA IDENTITY FULL"; fi
    fi
    sql CHECKPOINT >/dev/null
    start="$(sql 'SELECT pg_current_wal_insert_lsn()')"
    [[ -n "$declare_start" ]] || declare_start="$start"
    if [[ "$phase" == original || "$phase" == renamed ]]; then
        sql "SELECT json_build_object(
            'schemaVersion',1,'postgresMajor',$major,
            'systemIdentifier',(SELECT system_identifier::text FROM pg_control_system()),
            'timeline',(SELECT timeline_id FROM pg_control_checkpoint()),
            'documentdbVersion',(SELECT extversion FROM pg_extension WHERE extname='documentdb'),
            'validFromLsn','$start','validToLsn','FFFFFFFF/FFFFFFFF',
            'relations',(SELECT json_agg(json_build_object(
                'tblspaceOid',COALESCE(NULLIF(c.reltablespace,0),d.dattablespace)::bigint,
                'databaseOid',d.oid::bigint,'relfilenode',pg_relation_filenode(c.oid)::bigint,
                'collectionId',m.collection_id,'database',m.database_name,'collection',m.collection_name))
                FROM documentdb_api_catalog.collections m
                JOIN pg_class c ON c.oid=to_regclass('documentdb_data.documents_' || m.collection_id)
                JOIN pg_database d ON d.datname=current_database()
                WHERE m.database_name='wal_audit_mongo' AND m.collection_name IN ('items','renamed')))" > "$artifacts/$phase.manifest.json"
    fi
    driver "$phase"
    if [[ "$phase" == original || "$phase" == renamed ]]; then
        sql "SELECT json_agg(json_build_object('object_id',object_id::text,'document',document::text)) FROM $relation" > "$artifacts/$phase.storage.json"
    fi
    end="$(sql 'SELECT pg_current_wal_insert_lsn()')"
    printf '%s %s\n' "$start" "$end" > "$artifacts/$phase.range"
    if [[ "$phase" == original || "$phase" == renamed ]]; then
        "$runtime" run --rm --network none -v "$artifacts:/artifacts:rw" \
            --entrypoint python3 "$name-driver-image" -c \
            "import json,pathlib; p=pathlib.Path('/artifacts/$phase.manifest.json'); m=json.loads(p.read_text()); m['validToLsn']='$end'; p.write_text(json.dumps(m)+'\n')"
    fi
done
last="$(sql "SELECT pg_walfile_name('$end'::pg_lsn - 1)")"
first="$(sql "SELECT pg_walfile_name('$declare_start'::pg_lsn)")"
sql 'SELECT pg_switch_wal()' >/dev/null
while IFS= read -r segment; do
    [[ "$segment" =~ ^[0-9A-F]{24}$ ]]
    # Read-only SQL COPY of closed segments, never a live host PGDATA mount.
    "$runtime" exec "$name" psql -X -v ON_ERROR_STOP=1 -p 9712 -U documentdb -d postgres \
        -c "COPY (SELECT encode(pg_read_binary_file('pg_wal/$segment'),'hex')) TO STDOUT" \
        > "$artifacts/wal/$segment.hex"
done < <(sql "SELECT name FROM pg_ls_waldir() WHERE name ~ '^[0-9A-F]{24}$' AND name >= '$first' AND name <= '$last' ORDER BY name")
"$runtime" run --rm --network none -v "$artifacts:/artifacts:rw" "$name-driver-image" extract
for phase in create original rename renamed drop; do
    read -r start end < "$artifacts/$phase.range"
    args=(--wal-dir /artifacts/wal --format jsonl --from-lsn "$start" --to-lsn "$end" --postgres-major "$major" --show-postgres-records)
    if [[ "$phase" == original || "$phase" == renamed ]]; then
        args+=(--manifest "/artifacts/$phase.manifest.json")
        if [[ "$mode" == precision ]]; then args+=(--strict); fi
    fi
    "$runtime" run --rm --name "$name-audit" --network none --read-only \
        -v "$PWD/$binary:/audit:ro" -v "$artifacts:/artifacts:ro" \
        --entrypoint /audit "$toolchain" "${args[@]}" > "$artifacts/$phase.jsonl"
    if [[ "$phase" == original || "$phase" == renamed ]]; then
        "$runtime" run --rm --name "$name-audit" --network none --read-only \
            -v "$PWD/$binary:/audit:ro" -v "$artifacts:/artifacts:ro" \
            --entrypoint /audit "$toolchain" "${args[@]}" --redact-documents > "$artifacts/$phase.redacted.jsonl"
    fi
done
"$runtime" run --rm --network none -v "$artifacts:/artifacts:rw" "$name-driver-image" verify
echo "Synthetic-only test artifacts: $artifacts"
