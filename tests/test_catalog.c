#include "postgres.h"
#include "catalog.h"
#include "audit_private.h"
#include "access/heapam_xlog.h"
#include "access/htup_details.h"
#include "varatt.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static size_t
align_tuple(size_t offset, size_t alignment)
{
    size_t absolute = offset + SizeofHeapTupleHeader;
    return ((absolute + alignment - 1) & ~(alignment - 1)) -
           SizeofHeapTupleHeader;
}

static size_t
append_short(uint8 *data, size_t offset, const uint8 *value, size_t length)
{
    SET_VARSIZE_SHORT(data + offset, length + VARHDRSZ_SHORT);
    memcpy(data + offset + VARHDRSZ_SHORT, value, length);
    return offset + length + VARHDRSZ_SHORT;
}

static size_t
make_catalog_tuple(uint8 *tuple, unsigned natts, const char *database,
                   const char *collection, int64 collection_id, bool is_view)
{
    xl_heap_header header = {0};
    uint8 *data = tuple + SizeOfHeapHeader;
    size_t offset;
    static const uint8 empty_bson[5] = {5, 0, 0, 0, 0};
    memset(tuple, 0, 1024);
    header.t_infomask2 = natts;
    header.t_infomask = HEAP_HASNULL;
    header.t_hoff = MAXALIGN(SizeofHeapTupleHeader + BITMAPLEN(natts));
    memcpy(tuple, &header, SizeOfHeapHeader);
    data[0] = 0x27; /* database, collection, id, and optional view_definition */
    if (!is_view)
        data[0] &= ~(1U << 5);
    offset = header.t_hoff - SizeofHeapTupleHeader;
    offset = append_short(data, offset, (const uint8 *)database, strlen(database));
    offset = append_short(data, offset, (const uint8 *)collection, strlen(collection));
    offset = align_tuple(offset, 8);
    memcpy(data + offset, &collection_id, sizeof(collection_id));
    offset += sizeof(collection_id);
    if (is_view)
        offset = append_short(data, offset, empty_bson, sizeof(empty_bson));
    return SizeOfHeapHeader + offset;
}

static AuditCatalogInput
mutation(TransactionId xid, AuditCatalogHeapOperation operation,
         const uint8 *old_tuple, size_t old_length,
         const uint8 *new_tuple, size_t new_length,
         uint32 old_block, uint16 old_offset,
         uint32 new_block, uint16 new_offset, XLogRecPtr lsn)
{
    AuditCatalogInput input = {0};
    input.relation = (AuditCatalogLocator){1663, 5, 18468};
    input.operation = operation;
    input.outcome = AUDIT_CATALOG_TX_PENDING;
    input.xid = xid;
    input.record_lsn = lsn;
    input.old_tuple = old_tuple;
    input.old_tuple_length = old_length;
    input.new_tuple = new_tuple;
    input.new_tuple_length = new_length;
    input.old_tid = (AuditCatalogTid){old_block, old_offset, old_offset != 0};
    input.new_tid = (AuditCatalogTid){new_block, new_offset, new_offset != 0};
    return input;
}

static AuditCatalogInput
outcome(TransactionId xid, AuditCatalogTransactionOutcome tx, XLogRecPtr lsn)
{
    AuditCatalogInput input = {0};
    input.operation = AUDIT_CATALOG_HEAP_NONE;
    input.outcome = tx;
    input.xid = xid;
    input.outcome_lsn = lsn;
    return input;
}

int
main(void)
{
    uint8 sentinel[1024], created[1024], renamed[1024], aborted[1024];
    size_t sentinel_length, created_length, renamed_length, aborted_length;
    unsigned natts;
    const char *fingerprint;
    char error[512], directory[128], path[256];
    AuditCatalogCacheConfig config = {0};
    AuditCatalogCache *cache;
    AuditCatalogInput input;
    AuditCatalogDeltaList deltas;
    AuditManifest manifest;

    assert(audit_catalog_descriptor("0.111-0", &natts, &fingerprint,
                                    error, sizeof(error)) && natts == 9);
    assert(audit_catalog_descriptor("0.117-0", &natts, &fingerprint,
                                    error, sizeof(error)) && natts == 10);
    assert(!audit_catalog_descriptor("0.115-0", &natts, &fingerprint,
                                     error, sizeof(error)));

    snprintf(directory, sizeof(directory), "tests/catalog-cache-pg%d-%ld",
             PG_VERSION_NUM / 10000, (long)getpid());
    assert(mkdir(directory, 0700) == 0);
    snprintf(path, sizeof(path), "%s/catalog.sqlite", directory);
    config.path = path;
    config.mode = AUDIT_CATALOG_CACHE_NORMAL;
    config.coverage = AUDIT_CATALOG_COVERAGE_COMPLETE_FROM_ORIGIN;
    config.system_identifier = 7612345678901234567ULL;
    config.postgres_major = PG_VERSION_NUM / 10000;
    config.block_size = 8192;
    config.wal_segment_size = 16 * 1024 * 1024;
    config.timeline = 1;
    config.documentdb_version = "1.0-0";
    cache = audit_catalog_cache_open(&config, error, sizeof(error));
    assert(cache != NULL);

    sentinel_length = make_catalog_tuple(sentinel, 10, "audit",
                                         "system.dbSentinel", 6400, false);
    created_length = make_catalog_tuple(created, 10, "audit", "items", 6401, false);
    renamed_length = make_catalog_tuple(renamed, 10, "audit", "renamed", 6401, false);
    aborted_length = make_catalog_tuple(aborted, 10, "audit", "aborted", 6402, false);

    input = mutation(10, AUDIT_CATALOG_HEAP_INSERT, NULL, 0,
                     sentinel, sentinel_length, 0, 0, 1, 1, 100);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    input = mutation(10, AUDIT_CATALOG_HEAP_INSERT, NULL, 0,
                     created, created_length, 0, 0, 1, 2, 101);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    input = outcome(10, AUDIT_CATALOG_TX_COMMIT, 110);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    assert(deltas.count == 2);
    assert(deltas.items[0].operation == AUDIT_CATALOG_DATABASE_CREATE);
    assert(strcmp(deltas.items[0].after_database, "audit") == 0);
    assert(deltas.items[0].after_collection == NULL);
    assert(deltas.items[deltas.count - 1].operation == AUDIT_CATALOG_COLLECTION_CREATE);
    assert(strcmp(deltas.items[deltas.count - 1].after_collection, "items") == 0);
    assert(strcmp(deltas.items[deltas.count - 1].certainty, "inferred") == 0);
    assert(strstr(deltas.items[deltas.count - 1].descriptor_fingerprint,
                  "collections-v10"));
    audit_catalog_delta_list_free(&deltas);

    input = mutation(11, AUDIT_CATALOG_HEAP_UPDATE, created, created_length,
                     renamed, renamed_length, 1, 2, 1, 3, 120);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    input = outcome(11, AUDIT_CATALOG_TX_COMMIT, 130);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    assert(deltas.count == 1);
    assert(deltas.items[0].operation == AUDIT_CATALOG_COLLECTION_RENAME);
    assert(strcmp(deltas.items[0].before_collection, "items") == 0);
    assert(strcmp(deltas.items[0].after_collection, "renamed") == 0);
    assert(strcmp(deltas.items[0].evidence, "collections_catalog_update") == 0);
    audit_catalog_delta_list_free(&deltas);

    input = mutation(12, AUDIT_CATALOG_HEAP_INSERT, NULL, 0,
                     aborted, aborted_length, 0, 0, 2, 1, 140);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    input = outcome(12, AUDIT_CATALOG_TX_ABORT, 150);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    assert(deltas.count == 0);

    audit_catalog_cache_close(cache);
    cache = audit_catalog_cache_open(&config, error, sizeof(error));
    assert(cache != NULL);
    input = mutation(13, AUDIT_CATALOG_HEAP_DELETE, NULL, 0, NULL, 0,
                     1, 3, 0, 0, 160);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    input = outcome(13, AUDIT_CATALOG_TX_COMMIT, 170);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    assert(deltas.count == 1);
    assert(deltas.items[0].operation == AUDIT_CATALOG_COLLECTION_DROP);
    assert(strcmp(deltas.items[0].before_collection, "renamed") == 0);
    audit_catalog_delta_list_free(&deltas);

    input = mutation(14, AUDIT_CATALOG_HEAP_DELETE, NULL, 0, NULL, 0,
                     99, 9, 0, 0, 180);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    input = outcome(14, AUDIT_CATALOG_TX_COMMIT, 190);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    assert(deltas.count == 1);
    assert(deltas.items[0].operation == AUDIT_CATALOG_UNKNOWN);
    assert(strcmp(deltas.items[0].warning, "catalog_delete_state_missing") == 0);
    audit_catalog_delta_list_free(&deltas);

    input = mutation(20, AUDIT_CATALOG_HEAP_INSERT, NULL, 0,
                     aborted, aborted_length, 0, 0, 3, 1, 200);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    assert(audit_catalog_assign_parent(cache, 20, 21, error, sizeof(error)));
    input = outcome(21, AUDIT_CATALOG_TX_COMMIT, 210);
    assert(audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    assert(deltas.count == 1);
    assert(deltas.items[0].operation == AUDIT_CATALOG_COLLECTION_CREATE);
    assert(strcmp(deltas.items[0].after_collection, "aborted") == 0);
    audit_catalog_delta_list_free(&deltas);

    input = mutation(22, AUDIT_CATALOG_HEAP_INSERT, NULL, 0,
                     created, created_length, 0, 0, 4, 1, 195);
    assert(!audit_catalog_process(cache, &input, &deltas, error, sizeof(error)));
    assert(strstr(error, "precedes checkpoint") != NULL);

    char manifest_path[256];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", directory);
    FILE *manifest_file = fopen(manifest_path, "w");
    assert(manifest_file != NULL);
    assert(fprintf(manifest_file,
        "{\"schemaVersion\":2,\"postgresMajor\":%d,"
        "\"systemIdentifier\":\"7612345678901234567\",\"timeline\":1,"
        "\"documentdbVersion\":\"1.0-0\",\"validFromLsn\":\"0/1\","
        "\"validToLsn\":\"0/200\",\"relations\":[{\"kind\":\"collections_catalog\","
        "\"tblspaceOid\":1663,\"databaseOid\":5,\"relfilenode\":18468}]}",
        PG_VERSION_NUM / 10000) > 0);
    assert(fclose(manifest_file) == 0);
    assert(audit_manifest_load(manifest_path, &manifest, error, sizeof(error)));
    assert(manifest.schema_version == 2);
    assert(manifest.count == 1);
    assert(manifest.relations[0].kind == AUDIT_RELATION_COLLECTIONS_CATALOG);
    audit_manifest_free(&manifest);
    assert(unlink(manifest_path) == 0);

    audit_catalog_cache_close(cache);
    config.coverage = AUDIT_CATALOG_COVERAGE_PARTIAL;
    config.mode = AUDIT_CATALOG_CACHE_READONLY;
    cache = audit_catalog_cache_open(&config, error, sizeof(error));
    if (!cache)
        fprintf(stderr, "read-only cache open failed: %s\n", error);
    assert(cache != NULL);
    audit_catalog_cache_close(cache);

    AuditCatalogCacheConfig ephemeral = config;
    ephemeral.path = NULL;
    ephemeral.mode = AUDIT_CATALOG_CACHE_EPHEMERAL;
    cache = audit_catalog_cache_open(&ephemeral, error, sizeof(error));
    assert(cache != NULL);
    audit_catalog_cache_close(cache);

    config.mode = AUDIT_CATALOG_CACHE_NORMAL;
    cache = audit_catalog_cache_open(&config, error, sizeof(error));
    assert(cache != NULL);
    assert(audit_catalog_cache_mark_gap(cache, 220, error, sizeof(error)));
    audit_catalog_cache_close(cache);

    config.coverage = AUDIT_CATALOG_COVERAGE_COMPLETE_FROM_ORIGIN;
    config.mode = AUDIT_CATALOG_CACHE_REBUILD;
    cache = audit_catalog_cache_open(&config, error, sizeof(error));
    assert(cache != NULL);
    assert(audit_catalog_cache_publish_rebuild(cache, error, sizeof(error)));
    audit_catalog_cache_close(cache);

    assert(audit_catalog_cache_delete(path, error, sizeof(error)));
    assert(rmdir(directory) == 0);
    puts("catalog tuple, lifecycle, provenance, and persistent cache tests passed");
    return 0;
}
