#include "postgres.h"
#include "catalog.h"
#include "access/heapam_xlog.h"
#include "access/htup_details.h"
#include "varatt.h"
#include <sqlite3.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CATALOG_CACHE_VERSION 2
#define CATALOG_NAME_LIMIT (16U * 1024U * 1024U)

typedef struct CatalogRow
{
    int64 collection_id;
    char *database;
    char *collection;
    bool is_view;
    AuditCatalogTid tid;
    uint8 *tuple;
    size_t tuple_length;
    bool present;
    bool initial_present;
    char *initial_database;
    char *initial_collection;
    bool initial_is_view;
    XLogRecPtr first_lsn;
    XLogRecPtr last_lsn;
    AuditCatalogLocator relation;
} CatalogRow;

struct AuditCatalogCache
{
    sqlite3 *db;
    AuditCatalogCacheConfig config;
    char *active_path;
    char *opened_path;
    const char *fingerprint;
    unsigned natts;
};

static bool
catalog_error(char *error, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(error, size, format, args);
    va_end(args);
    return false;
}

static const char *
coverage_name(AuditCatalogCoverage coverage)
{
    switch (coverage)
    {
        case AUDIT_CATALOG_COVERAGE_ROW_LOCAL: return "row-local";
        case AUDIT_CATALOG_COVERAGE_COMPLETE_FROM_CACHE: return "complete-from-cache";
        case AUDIT_CATALOG_COVERAGE_COMPLETE_FROM_ORIGIN: return "complete-from-origin";
        default: return "partial";
    }
}

bool
audit_catalog_descriptor(const char *version, unsigned *natts,
                         const char **fingerprint, char *error, size_t size)
{
    static const char *nine[] = {
        "0.100-0", "0.101-0", "0.102-0", "0.103-0", "0.104-0", "0.105-0",
        "0.106-0", "0.107-0", "0.108-0", "0.109-0", "0.110-0", "0.111-0"
    };
    static const char *ten[] = {
        "0.112-0", "0.113-0", "0.114-0", "0.116-0", "0.117-0", "1.0-0"
    };
    if (!version || !natts || !fingerprint)
        return catalog_error(error, size, "catalog: invalid descriptor request");
    for (size_t i = 0; i < sizeof(nine) / sizeof(nine[0]); i++)
        if (!strcmp(version, nine[i]))
        {
            *natts = 9;
            *fingerprint =
                "collections-v9:"
                "1:database_name:text:-1:i:x:notnull;"
                "2:collection_name:text:-1:i:x:notnull;"
                "3:collection_id:int8:8:d:p:notnull;"
                "4:shard_key:bson:-1:i:x:null;"
                "5:collection_uuid:uuid:16:c:p:null;"
                "6:view_definition:bson:-1:i:x:null;"
                "7:validator:bson:-1:i:x:null;"
                "8:validation_level:text:-1:i:x:null;"
                "9:validation_action:text:-1:i:x:null";
            return true;
        }
    for (size_t i = 0; i < sizeof(ten) / sizeof(ten[0]); i++)
        if (!strcmp(version, ten[i]))
        {
            *natts = 10;
            *fingerprint =
                "collections-v10:"
                "1:database_name:text:-1:i:x:notnull;"
                "2:collection_name:text:-1:i:x:notnull;"
                "3:collection_id:int8:8:d:p:notnull;"
                "4:shard_key:bson:-1:i:x:null;"
                "5:collection_uuid:uuid:16:c:p:null;"
                "6:view_definition:bson:-1:i:x:null;"
                "7:validator:bson:-1:i:x:null;"
                "8:validation_level:text:-1:i:x:null;"
                "9:validation_action:text:-1:i:x:null;"
                "10:options:bson:-1:i:x:null";
            return true;
        }
    return catalog_error(error, size,
                         "catalog: unsupported exact DocumentDB extension version");
}

static size_t
align_offset(size_t offset, size_t alignment)
{
    size_t absolute = offset + SizeofHeapTupleHeader;
    return ((absolute + alignment - 1) & ~(alignment - 1)) -
           SizeofHeapTupleHeader;
}

static bool
attribute_nonnull(const uint8 *bitmap, unsigned attribute)
{
    return (bitmap[attribute / 8] & (1U << (attribute % 8))) != 0;
}

static bool
varlena_bounds(const uint8 *data, size_t length, size_t *offset,
               size_t *header, size_t *bytes, bool require_plain,
               char *error, size_t size)
{
    uint32 word;
    size_t pos = *offset;
    if (pos >= length)
        return catalog_error(error, size, "catalog: missing varlena attribute");
    if (data[pos] == 0)
        pos = align_offset(pos, 4);
    if (pos >= length)
        return catalog_error(error, size, "catalog: truncated varlena alignment");
    if (VARATT_IS_1B_E(data + pos))
    {
        if (require_plain)
            return catalog_error(error, size,
                                 "catalog: external identity value is unavailable");
        *header = VARHDRSZ_EXTERNAL;
        *bytes = VARSIZE_EXTERNAL(data + pos);
    }
    else if (VARATT_IS_1B(data + pos))
    {
        *header = VARHDRSZ_SHORT;
        *bytes = VARSIZE_1B(data + pos);
    }
    else
    {
        if (length - pos < VARHDRSZ)
            return catalog_error(error, size, "catalog: truncated varlena header");
        memcpy(&word, data + pos, sizeof(word));
        if (require_plain && VARATT_IS_4B_C(data + pos))
            return catalog_error(error, size,
                                 "catalog: compressed identity value is unavailable");
        *header = VARHDRSZ;
#ifdef WORDS_BIGENDIAN
        *bytes = word & 0x3fffffff;
#else
        *bytes = word >> 2;
#endif
    }
    if (*bytes < *header || *bytes > length - pos)
        return catalog_error(error, size, "catalog: invalid varlena attribute");
    *offset = pos;
    return true;
}

static bool
read_text(const uint8 *data, size_t length, size_t *offset, char **value,
          char *error, size_t size)
{
    size_t header, bytes, pos = *offset;
    if (!varlena_bounds(data, length, &pos, &header, &bytes, true, error, size))
        return false;
    if (bytes - header > CATALOG_NAME_LIMIT ||
        memchr(data + pos + header, '\0', bytes - header))
        return catalog_error(error, size, "catalog: invalid or oversized text attribute");
    *value = malloc(bytes - header + 1);
    if (!*value)
        return catalog_error(error, size, "catalog: out of memory");
    memcpy(*value, data + pos + header, bytes - header);
    (*value)[bytes - header] = '\0';
    *offset = pos + bytes;
    return true;
}

static bool
skip_varlena(const uint8 *data, size_t length, size_t *offset,
             char *error, size_t size)
{
    size_t header, bytes, pos = *offset;
    if (!varlena_bounds(data, length, &pos, &header, &bytes, false, error, size))
        return false;
    *offset = pos + bytes;
    return true;
}

static void
row_free(CatalogRow *row)
{
    if (!row)
        return;
    free(row->database);
    free(row->collection);
    free(row->tuple);
    free(row->initial_database);
    free(row->initial_collection);
    memset(row, 0, sizeof(*row));
}

static bool
decode_tuple(AuditCatalogCache *cache, const uint8 *tuple, size_t tuple_length,
             CatalogRow *row, char *error, size_t size)
{
    xl_heap_header header;
    const uint8 *data;
    const uint8 *bitmap = NULL;
    size_t length, offset;
    unsigned natts;
    if (!tuple || tuple_length < SizeOfHeapHeader)
        return catalog_error(error, size, "catalog: tuple bytes unavailable");
    memcpy(&header, tuple, SizeOfHeapHeader);
    natts = header.t_infomask2 & HEAP_NATTS_MASK;
    if (natts != cache->natts)
        return catalog_error(error, size, "catalog: descriptor attribute count mismatch");
    if (header.t_hoff != MAXALIGN(SizeofHeapTupleHeader +
            ((header.t_infomask & HEAP_HASNULL) ? BITMAPLEN(natts) : 0)))
        return catalog_error(error, size, "catalog: invalid tuple data offset");
    data = tuple + SizeOfHeapHeader;
    length = tuple_length - SizeOfHeapHeader;
    offset = header.t_hoff - SizeofHeapTupleHeader;
    if (offset > length)
        return catalog_error(error, size, "catalog: truncated tuple bitmap or padding");
    if (header.t_infomask & HEAP_HASNULL)
        bitmap = data;
#define NONNULL(att) (!bitmap || attribute_nonnull(bitmap, (att)))
    if (!NONNULL(0) || !NONNULL(1) || !NONNULL(2))
        return catalog_error(error, size, "catalog: required identity attribute is NULL");
    if (!read_text(data, length, &offset, &row->database, error, size) ||
        !read_text(data, length, &offset, &row->collection, error, size))
        goto fail;
    offset = align_offset(offset, 8);
    if (offset > length || length - offset < sizeof(int64))
    {
        catalog_error(error, size, "catalog: truncated collection_id");
        goto fail;
    }
    memcpy(&row->collection_id, data + offset, sizeof(row->collection_id));
    offset += sizeof(int64);
    if (row->collection_id <= 0)
    {
        catalog_error(error, size, "catalog: invalid collection_id");
        goto fail;
    }
    for (unsigned att = 3; att < natts; att++)
    {
        if (!NONNULL(att))
            continue;
        if (att == 4)
        {
            if (offset > length || length - offset < 16)
            {
                catalog_error(error, size, "catalog: truncated UUID attribute");
                goto fail;
            }
            offset += 16;
        }
        else if (!skip_varlena(data, length, &offset, error, size))
            goto fail;
        if (att == 5)
            row->is_view = true;
    }
    if (offset != length)
    {
        catalog_error(error, size, "catalog: unexpected tuple trailing bytes");
        goto fail;
    }
    row->tuple = malloc(tuple_length);
    if (!row->tuple)
    {
        catalog_error(error, size, "catalog: out of memory");
        goto fail;
    }
    memcpy(row->tuple, tuple, tuple_length);
    row->tuple_length = tuple_length;
    row->present = true;
    return true;
fail:
    row_free(row);
    return false;
#undef NONNULL
}

static bool
exec_sql(sqlite3 *db, const char *sql, char *error, size_t size)
{
    char *sqlite_error = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &sqlite_error) != SQLITE_OK)
    {
        catalog_error(error, size, "catalog cache: %s",
                      sqlite_error ? sqlite_error : sqlite3_errmsg(db));
        sqlite3_free(sqlite_error);
        return false;
    }
    return true;
}

static bool
private_parent(const char *path, char **directory, char *error, size_t size)
{
    char *copy, *slash;
    struct stat st;
    if (!path || !*path)
        return catalog_error(error, size, "catalog cache: empty path");
    copy = strdup(path);
    if (!copy)
        return catalog_error(error, size, "catalog cache: out of memory");
    slash = strrchr(copy, '/');
    if (slash)
    {
        if (slash == copy)
            slash[1] = '\0';
        else
            *slash = '\0';
    }
    else
    {
        free(copy);
        copy = strdup(".");
    }
    if (!copy || lstat(copy, &st) || !S_ISDIR(st.st_mode) ||
        S_ISLNK(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700)
    {
        free(copy);
        return catalog_error(error, size,
            "catalog cache: parent must be a non-symlink owner-only 0700 directory");
    }
    *directory = copy;
    return true;
}

static bool
prepare_file(const char *path, bool readonly, char *error, size_t size)
{
    struct stat st;
    int fd;
    if (lstat(path, &st) == 0)
    {
        if (!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode) ||
            st.st_uid != geteuid() || (st.st_mode & 0777) != 0600)
            return catalog_error(error, size,
                "catalog cache: file must be regular, owner-owned, and mode 0600");
        return true;
    }
    if (errno != ENOENT || readonly)
        return catalog_error(error, size, "catalog cache: cannot access cache file");
    fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0)
        return catalog_error(error, size, "catalog cache: cannot create cache file");
    if (close(fd))
        return catalog_error(error, size, "catalog cache: cannot close cache file");
    return true;
}

static bool
bind_metadata(sqlite3 *db, const char *key, const char *value,
              bool initialize, char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    const char *sql = initialize ?
        "INSERT INTO metadata(key,value) VALUES(?1,?2)" :
        "SELECT value FROM metadata WHERE key=?1";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(db));
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    if (initialize)
        sqlite3_bind_text(stmt, 2, value, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (initialize ? rc != SQLITE_DONE :
        (rc != SQLITE_ROW || strcmp((const char *)sqlite3_column_text(stmt, 0), value)))
    {
        sqlite3_finalize(stmt);
        return catalog_error(error, size, "catalog cache: provenance mismatch for %s", key);
    }
    sqlite3_finalize(stmt);
    return true;
}

static bool
load_coverage(AuditCatalogCache *cache, bool initialize,
              char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    if (initialize)
    {
        char value[16];
        snprintf(value, sizeof(value), "%u", cache->config.coverage);
        return bind_metadata(cache->db, "coverage", value, true, error, size);
    }
    if (sqlite3_prepare_v2(cache->db,
        "SELECT value FROM metadata WHERE key='coverage'", -1,
        &stmt, NULL) != SQLITE_OK)
        return catalog_error(error, size, "catalog cache: %s",
                             sqlite3_errmsg(cache->db));
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return catalog_error(error, size,
                             "catalog cache: missing coverage metadata");
    }
    const char *text = (const char *)sqlite3_column_text(stmt, 0);
    char *end = NULL;
    unsigned long value = text ? strtoul(text, &end, 10) : ULONG_MAX;
    if (!text || !end || *end ||
        value > AUDIT_CATALOG_COVERAGE_COMPLETE_FROM_ORIGIN)
    {
        sqlite3_finalize(stmt);
        return catalog_error(error, size,
                             "catalog cache: invalid coverage metadata");
    }
    cache->config.coverage = (AuditCatalogCoverage)value;
    sqlite3_finalize(stmt);
    return true;
}

static bool
cache_schema(AuditCatalogCache *cache, char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    bool initialize;
    char number[64];
    static const char *schema =
        "CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
        "CREATE TABLE rows(collection_id INTEGER PRIMARY KEY,database_name TEXT NOT NULL,"
        " collection_name TEXT NOT NULL,is_view INTEGER NOT NULL,tablespace INTEGER NOT NULL,"
        " database_oid INTEGER NOT NULL,relfilenode INTEGER NOT NULL,block INTEGER NOT NULL,"
        " offnum INTEGER NOT NULL,tuple BLOB NOT NULL,last_lsn TEXT NOT NULL,"
        " UNIQUE(database_name,collection_name));"
        "CREATE TABLE pending(seq INTEGER PRIMARY KEY AUTOINCREMENT,xid INTEGER NOT NULL,"
        " record_lsn TEXT NOT NULL,operation_ordinal INTEGER NOT NULL,"
        " operation INTEGER NOT NULL,tablespace INTEGER NOT NULL,"
        " database_oid INTEGER NOT NULL,relfilenode INTEGER NOT NULL,"
        " old_block INTEGER,old_offnum INTEGER,new_block INTEGER,new_offnum INTEGER,"
        " old_tuple BLOB,new_tuple BLOB,UNIQUE(xid,record_lsn,operation_ordinal));"
        "CREATE INDEX pending_xid ON pending(xid,seq);"
        "CREATE TABLE ledger(xid INTEGER NOT NULL,record_lsn TEXT NOT NULL,"
        " operation_ordinal INTEGER NOT NULL,operation INTEGER NOT NULL,"
        " tablespace INTEGER NOT NULL,database_oid INTEGER NOT NULL,"
        " relfilenode INTEGER NOT NULL,old_block INTEGER,old_offnum INTEGER,"
        " new_block INTEGER,new_offnum INTEGER,old_tuple BLOB,new_tuple BLOB,"
        " PRIMARY KEY(record_lsn,operation_ordinal));"
        "CREATE TABLE checkpoint(singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
        " replay_lsn TEXT NOT NULL,commit_lsn TEXT NOT NULL);"
        "INSERT INTO checkpoint VALUES(1,'0','0');"
        "CREATE TABLE page_relations(tablespace INTEGER NOT NULL,database_oid INTEGER NOT NULL,"
        " relfilenode INTEGER NOT NULL,fork INTEGER NOT NULL,generation INTEGER NOT NULL,"
        " lifecycle INTEGER NOT NULL,applied_lsn TEXT NOT NULL,"
        " PRIMARY KEY(tablespace,database_oid,relfilenode,fork,generation,applied_lsn));"
        "CREATE TABLE page_tuples(tablespace INTEGER NOT NULL,database_oid INTEGER NOT NULL,"
        " relfilenode INTEGER NOT NULL,fork INTEGER NOT NULL,generation INTEGER NOT NULL,"
        " block INTEGER NOT NULL,offnum INTEGER NOT NULL,tuple BLOB,slot_state INTEGER NOT NULL,"
        " trust INTEGER NOT NULL,source INTEGER NOT NULL,applied_lsn TEXT NOT NULL,"
        " PRIMARY KEY(tablespace,database_oid,relfilenode,fork,generation,block,offnum,applied_lsn));"
        "CREATE INDEX page_tuple_lookup ON page_tuples(tablespace,database_oid,relfilenode,"
        " fork,generation,block,offnum,applied_lsn);"
        "CREATE TABLE page_invalidations(scope INTEGER NOT NULL,tablespace INTEGER,"
        " database_oid INTEGER,relfilenode INTEGER,fork INTEGER,generation INTEGER,"
        " block INTEGER,applied_lsn TEXT NOT NULL,"
        " PRIMARY KEY(scope,tablespace,database_oid,relfilenode,fork,generation,block,applied_lsn));"
        "PRAGMA user_version=2;";
    if (sqlite3_prepare_v2(cache->db, "PRAGMA user_version", -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_ROW)
        return catalog_error(error, size, "catalog cache: cannot read schema version");
    initialize = sqlite3_column_int(stmt, 0) == 0;
    sqlite3_finalize(stmt);
    if (initialize && cache->config.mode == AUDIT_CATALOG_CACHE_READONLY)
        return catalog_error(error, size, "catalog cache: read-only cache is absent");
    if (initialize && !exec_sql(cache->db, schema, error, size))
        return false;
    if (!initialize)
    {
        if (sqlite3_prepare_v2(cache->db, "PRAGMA user_version", -1, &stmt, NULL) != SQLITE_OK ||
            sqlite3_step(stmt) != SQLITE_ROW || sqlite3_column_int(stmt, 0) != CATALOG_CACHE_VERSION)
            return catalog_error(error, size, "catalog cache: unsupported schema version");
        sqlite3_finalize(stmt);
    }
#define META_NUMBER(key, field) do { \
    snprintf(number, sizeof(number), "%" PRIu64, (uint64)(field)); \
    if (!bind_metadata(cache->db, (key), number, initialize, error, size)) return false; \
} while (0)
    META_NUMBER("cache_version", CATALOG_CACHE_VERSION);
    META_NUMBER("system_identifier", cache->config.system_identifier);
    META_NUMBER("postgres_major", cache->config.postgres_major);
    META_NUMBER("block_size", cache->config.block_size);
    META_NUMBER("wal_segment_size", cache->config.wal_segment_size);
    META_NUMBER("timeline", cache->config.timeline);
#undef META_NUMBER
    if (!load_coverage(cache, initialize, error, size) ||
        !bind_metadata(cache->db, "documentdb_version",
                       cache->config.documentdb_version, initialize, error, size) ||
        !bind_metadata(cache->db, "descriptor_fingerprint",
                       cache->fingerprint, initialize, error, size))
        return false;
    return true;
}

static bool
cache_integrity(sqlite3 *db, char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &stmt, NULL) != SQLITE_OK)
        return catalog_error(error, size, "catalog cache: cannot start integrity check");
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW ||
        strcmp((const char *)sqlite3_column_text(stmt, 0), "ok"))
    {
        sqlite3_finalize(stmt);
        return catalog_error(error, size, "catalog cache: integrity check failed");
    }
    sqlite3_finalize(stmt);
    return true;
}

AuditCatalogCache *
audit_catalog_cache_open(const AuditCatalogCacheConfig *config,
                         char *error, size_t size)
{
    AuditCatalogCache *cache;
    char *directory = NULL;
    int flags;
    if (!config || !config->documentdb_version ||
        !config->postgres_major || !config->system_identifier ||
        !config->block_size || !config->wal_segment_size || !config->timeline)
    {
        catalog_error(error, size, "catalog cache: incomplete provenance");
        return NULL;
    }
    cache = calloc(1, sizeof(*cache));
    if (!cache)
    {
        catalog_error(error, size, "catalog cache: out of memory");
        return NULL;
    }
    cache->config = *config;
    if (!audit_catalog_descriptor(config->documentdb_version, &cache->natts,
                                  &cache->fingerprint, error, size))
        goto fail;
    if (config->mode == AUDIT_CATALOG_CACHE_EPHEMERAL)
        cache->opened_path = strdup(":memory:");
    else
    {
        if (!private_parent(config->path, &directory, error, size))
            goto fail;
        cache->active_path = strdup(config->path);
        if (config->mode == AUDIT_CATALOG_CACHE_REBUILD)
        {
            struct stat candidate;
            size_t length = strlen(config->path) + sizeof(".candidate");
            cache->opened_path = malloc(length);
            if (cache->opened_path)
                snprintf(cache->opened_path, length, "%s.candidate", config->path);
            if (cache->opened_path && lstat(cache->opened_path, &candidate) == 0)
            {
                catalog_error(error, size,
                    "catalog cache: rebuild candidate already exists; preserving it");
                goto fail;
            }
            if (cache->opened_path && errno != ENOENT)
            {
                catalog_error(error, size,
                    "catalog cache: cannot inspect rebuild candidate");
                goto fail;
            }
        }
        else
            cache->opened_path = strdup(config->path);
        if (!cache->active_path || !cache->opened_path ||
            !prepare_file(cache->opened_path,
                          config->mode == AUDIT_CATALOG_CACHE_READONLY,
                          error, size))
            goto fail;
    }
    flags = config->mode == AUDIT_CATALOG_CACHE_READONLY ?
        SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (sqlite3_open_v2(cache->opened_path, &cache->db, flags, NULL) != SQLITE_OK)
    {
        catalog_error(error, size, "catalog cache: %s",
                      cache->db ? sqlite3_errmsg(cache->db) : "open failed");
        goto fail;
    }
    sqlite3_busy_timeout(cache->db, 5000);
    if (!exec_sql(cache->db, config->mode == AUDIT_CATALOG_CACHE_READONLY ?
                             "PRAGMA foreign_keys=ON;PRAGMA query_only=ON;" :
                             "PRAGMA foreign_keys=ON;PRAGMA synchronous=FULL;"
                             "PRAGMA journal_mode=DELETE;", error, size) ||
        !cache_schema(cache, error, size) ||
        !cache_integrity(cache->db, error, size))
        goto fail;
    free(directory);
    return cache;
fail:
    free(directory);
    audit_catalog_cache_close(cache);
    return NULL;
}

static bool
same_blob(sqlite3_stmt *stmt, int column, const uint8 *bytes, size_t length)
{
    if (!bytes)
        return sqlite3_column_type(stmt, column) == SQLITE_NULL;
    return sqlite3_column_type(stmt, column) == SQLITE_BLOB &&
           sqlite3_column_bytes(stmt, column) == (int)length &&
           !memcmp(sqlite3_column_blob(stmt, column), bytes, length);
}

static bool
mutation_already_seen(AuditCatalogCache *cache, const AuditCatalogInput *input,
                      const char *lsn, bool *seen, char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    *seen = false;
    if (sqlite3_prepare_v2(cache->db,
        "SELECT operation,tablespace,database_oid,relfilenode,"
        "old_block,old_offnum,new_block,new_offnum,old_tuple,new_tuple FROM pending "
        "WHERE xid=?1 AND record_lsn=?2 AND operation_ordinal=?3 "
        "UNION ALL SELECT operation,tablespace,database_oid,relfilenode,"
        "old_block,old_offnum,new_block,new_offnum,old_tuple,new_tuple FROM ledger "
        "WHERE xid=?1 AND record_lsn=?2 AND operation_ordinal=?3 LIMIT 1",
        -1, &stmt, NULL) != SQLITE_OK)
        return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
    sqlite3_bind_int64(stmt, 1, input->xid);
    sqlite3_bind_text(stmt, 2, lsn, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, input->operation_ordinal);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE)
    {
        sqlite3_finalize(stmt);
        return true;
    }
    if (rc != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
    }
    *seen = true;
    bool same = sqlite3_column_int(stmt, 0) == (int)input->operation &&
        sqlite3_column_int64(stmt, 1) == input->relation.tablespace &&
        sqlite3_column_int64(stmt, 2) == input->relation.database_oid &&
        sqlite3_column_int64(stmt, 3) == input->relation.relfilenode &&
        ((!input->old_tid.valid && sqlite3_column_type(stmt, 4) == SQLITE_NULL) ||
         (input->old_tid.valid &&
          sqlite3_column_int64(stmt, 4) == input->old_tid.block &&
          sqlite3_column_int(stmt, 5) == input->old_tid.offset)) &&
        ((!input->new_tid.valid && sqlite3_column_type(stmt, 6) == SQLITE_NULL) ||
         (input->new_tid.valid &&
          sqlite3_column_int64(stmt, 6) == input->new_tid.block &&
          sqlite3_column_int(stmt, 7) == input->new_tid.offset)) &&
        same_blob(stmt, 8, input->old_tuple, input->old_tuple_length) &&
        same_blob(stmt, 9, input->new_tuple, input->new_tuple_length);
    sqlite3_finalize(stmt);
    return same ? true :
        catalog_error(error, size,
                      "catalog cache: divergent mutation at existing LSN/ordinal");
}

static bool
checkpoint_lsn(AuditCatalogCache *cache, const char *column,
               XLogRecPtr *lsn, char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    char sql[96];
    int rc;
    snprintf(sql, sizeof(sql),
             "SELECT %s FROM checkpoint WHERE singleton=1", column);
    if (sqlite3_prepare_v2(cache->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return catalog_error(error, size, "catalog cache: %s",
                             sqlite3_errmsg(cache->db));
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return catalog_error(error, size,
                             "catalog cache: missing checkpoint");
    }
    const char *text = (const char *)sqlite3_column_text(stmt, 0);
    char *end = NULL;
    unsigned long long value = text ? strtoull(text, &end, 10) : 0;
    if (!text || !end || *end)
    {
        sqlite3_finalize(stmt);
        return catalog_error(error, size,
                             "catalog cache: invalid checkpoint");
    }
    *lsn = (XLogRecPtr)value;
    sqlite3_finalize(stmt);
    return true;
}

static bool
stage_mutation(AuditCatalogCache *cache, const AuditCatalogInput *input,
               char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    char lsn[32];
    int rc;
    bool seen;
    if (cache->config.mode == AUDIT_CATALOG_CACHE_READONLY)
        return catalog_error(error, size, "catalog cache: cannot stage in read-only mode");
    if (!input->xid || input->operation == AUDIT_CATALOG_HEAP_NONE)
        return catalog_error(error, size, "catalog: mutation requires XID and operation");
    snprintf(lsn, sizeof(lsn), "%" PRIu64, (uint64)input->record_lsn);
    if (!mutation_already_seen(cache, input, lsn, &seen, error, size))
        return false;
    if (seen)
        return true;
    XLogRecPtr replay_lsn;
    if (!checkpoint_lsn(cache, "replay_lsn", &replay_lsn, error, size))
        return false;
    if (input->record_lsn <= replay_lsn)
        return catalog_error(error, size,
            "catalog cache: mutation precedes checkpoint without matching ledger entry");
    if (sqlite3_prepare_v2(cache->db,
        "INSERT INTO pending(xid,record_lsn,operation_ordinal,operation,tablespace,"
        "database_oid,relfilenode,old_block,old_offnum,new_block,new_offnum,"
        "old_tuple,new_tuple) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        -1, &stmt, NULL) != SQLITE_OK)
        return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
    sqlite3_bind_int64(stmt, 1, input->xid);
    sqlite3_bind_text(stmt, 2, lsn, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, input->operation_ordinal);
    sqlite3_bind_int(stmt, 4, input->operation);
    sqlite3_bind_int64(stmt, 5, input->relation.tablespace);
    sqlite3_bind_int64(stmt, 6, input->relation.database_oid);
    sqlite3_bind_int64(stmt, 7, input->relation.relfilenode);
    if (input->old_tid.valid)
    {
        sqlite3_bind_int64(stmt, 8, input->old_tid.block);
        sqlite3_bind_int(stmt, 9, input->old_tid.offset);
    }
    if (input->new_tid.valid)
    {
        sqlite3_bind_int64(stmt, 10, input->new_tid.block);
        sqlite3_bind_int(stmt, 11, input->new_tid.offset);
    }
    if (input->old_tuple)
        sqlite3_bind_blob64(stmt, 12, input->old_tuple, input->old_tuple_length,
                            SQLITE_TRANSIENT);
    if (input->new_tuple)
        sqlite3_bind_blob64(stmt, 13, input->new_tuple, input->new_tuple_length,
                            SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_DONE)
        return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
    return true;
}

static bool
append_delta(AuditCatalogCache *cache, AuditCatalogDeltaList *list,
             AuditCatalogOperation operation, const CatalogRow *row,
             TransactionId xid, XLogRecPtr commit_lsn, const char *warning,
             char *error, size_t size)
{
    AuditCatalogDelta *grown = realloc(list->items,
                                      (list->count + 1) * sizeof(*grown));
    AuditCatalogDelta *delta;
    if (!grown)
        return catalog_error(error, size, "catalog: out of memory");
    list->items = grown;
    delta = &list->items[list->count++];
    memset(delta, 0, sizeof(*delta));
    delta->operation = operation;
    delta->certainty = operation == AUDIT_CATALOG_UNKNOWN ? "incomplete" : "inferred";
    delta->coverage = coverage_name(cache->config.coverage);
    delta->warning = warning;
    delta->relation = row->relation;
    delta->xid = xid;
    delta->event_lsn = row->first_lsn;
    delta->commit_lsn = commit_lsn;
    delta->collection_id = row->collection_id;
    delta->is_view = row->is_view;
    delta->descriptor_fingerprint = cache->fingerprint;
    delta->evidence = operation == AUDIT_CATALOG_UNKNOWN ?
        "collections_catalog_mutation" :
        (row->initial_present && row->present ? "collections_catalog_update" :
         (row->present ? "collections_catalog_insert" : "collections_catalog_delete"));
    if (row->initial_present)
    {
        delta->before_database = strdup(row->initial_database);
        if (operation != AUDIT_CATALOG_DATABASE_CREATE)
            delta->before_collection = strdup(row->initial_collection);
    }
    if (row->present)
    {
        delta->after_database = strdup(row->database);
        if (operation != AUDIT_CATALOG_DATABASE_CREATE)
            delta->after_collection = strdup(row->collection);
    }
    if ((row->initial_present && (!delta->before_database ||
             (operation != AUDIT_CATALOG_DATABASE_CREATE && !delta->before_collection))) ||
        (row->present && (!delta->after_database ||
             (operation != AUDIT_CATALOG_DATABASE_CREATE && !delta->after_collection))))
        return catalog_error(error, size, "catalog: out of memory");
    if (operation == AUDIT_CATALOG_DATABASE_CREATE)
    {
        delta->collection_id = 0;
        delta->is_view = false;
    }
    return true;
}

static bool
database_existed(AuditCatalogCache *cache, const char *database, bool *existed,
                 char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    if (sqlite3_prepare_v2(cache->db,
        "SELECT 1 FROM rows WHERE database_name=?1 "
        "AND collection_name<>'system.dbSentinel' LIMIT 1",
        -1, &stmt, NULL) != SQLITE_OK)
        return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
    sqlite3_bind_text(stmt, 1, database, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    *existed = rc == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return (rc == SQLITE_ROW || rc == SQLITE_DONE) ? true :
        catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
}

static bool
has_database_delta(const AuditCatalogDeltaList *deltas, const char *database)
{
    for (size_t i = 0; i < deltas->count; i++)
        if (deltas->items[i].operation == AUDIT_CATALOG_DATABASE_CREATE &&
            deltas->items[i].after_database &&
            !strcmp(deltas->items[i].after_database, database))
            return true;
    return false;
}

static bool
creates_database_sentinel(const CatalogRow *rows, size_t count,
                          const char *database)
{
    for (size_t i = 0; i < count; i++)
        if (!rows[i].initial_present && rows[i].present &&
            rows[i].database && rows[i].collection &&
            !strcmp(rows[i].database, database) &&
            !strcmp(rows[i].collection, "system.dbSentinel"))
            return true;
    return false;
}

static int
delta_priority(AuditCatalogOperation operation)
{
    switch (operation)
    {
        case AUDIT_CATALOG_DATABASE_CREATE: return 0;
        case AUDIT_CATALOG_COLLECTION_DROP:
        case AUDIT_CATALOG_VIEW_DROP: return 1;
        case AUDIT_CATALOG_COLLECTION_RENAME:
        case AUDIT_CATALOG_VIEW_RENAME: return 2;
        case AUDIT_CATALOG_COLLECTION_CREATE:
        case AUDIT_CATALOG_VIEW_CREATE: return 3;
        default: return 4;
    }
}

static int
compare_delta(const void *left, const void *right)
{
    const AuditCatalogDelta *a = left, *b = right;
    int ap = delta_priority(a->operation), bp = delta_priority(b->operation);
    if (ap != bp)
        return ap < bp ? -1 : 1;
    if (a->collection_id != b->collection_id)
        return a->collection_id < b->collection_id ? -1 : 1;
    return 0;
}

static ssize_t
find_work_row(CatalogRow *rows, size_t count, int64 collection_id)
{
    for (size_t i = 0; i < count; i++)
        if (rows[i].collection_id == collection_id)
            return (ssize_t)i;
    return -1;
}

static bool
load_committed_row(AuditCatalogCache *cache, int64 collection_id,
                   const AuditCatalogLocator *relation,
                   const AuditCatalogTid *tid, CatalogRow *row,
                   char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    const char *sql = collection_id ?
        "SELECT collection_id,database_name,collection_name,is_view,tablespace,"
        "database_oid,relfilenode,block,offnum,tuple,last_lsn FROM rows WHERE collection_id=?1" :
        "SELECT collection_id,database_name,collection_name,is_view,tablespace,"
        "database_oid,relfilenode,block,offnum,tuple,last_lsn FROM rows "
        "WHERE block=?1 AND offnum=?2 AND tablespace=?3 "
        "AND database_oid=?4 AND relfilenode=?5";
    if (sqlite3_prepare_v2(cache->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
    if (collection_id)
        sqlite3_bind_int64(stmt, 1, collection_id);
    else
    {
        sqlite3_bind_int64(stmt, 1, tid->block);
        sqlite3_bind_int(stmt, 2, tid->offset);
        sqlite3_bind_int64(stmt, 3, relation->tablespace);
        sqlite3_bind_int64(stmt, 4, relation->database_oid);
        sqlite3_bind_int64(stmt, 5, relation->relfilenode);
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE)
    {
        sqlite3_finalize(stmt);
        return true;
    }
    if (rc != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
    }
    row->collection_id = sqlite3_column_int64(stmt, 0);
    row->database = strdup((const char *)sqlite3_column_text(stmt, 1));
    row->collection = strdup((const char *)sqlite3_column_text(stmt, 2));
    row->is_view = sqlite3_column_int(stmt, 3) != 0;
    row->relation.tablespace = sqlite3_column_int64(stmt, 4);
    row->relation.database_oid = sqlite3_column_int64(stmt, 5);
    row->relation.relfilenode = sqlite3_column_int64(stmt, 6);
    row->tid.block = sqlite3_column_int64(stmt, 7);
    row->tid.offset = sqlite3_column_int(stmt, 8);
    row->tid.valid = true;
    row->tuple_length = sqlite3_column_bytes(stmt, 9);
    row->tuple = malloc(row->tuple_length);
    if (row->tuple)
        memcpy(row->tuple, sqlite3_column_blob(stmt, 9), row->tuple_length);
    row->last_lsn = strtoull((const char *)sqlite3_column_text(stmt, 10), NULL, 10);
    row->present = row->initial_present = true;
    row->initial_database = row->database ? strdup(row->database) : NULL;
    row->initial_collection = row->collection ? strdup(row->collection) : NULL;
    row->initial_is_view = row->is_view;
    sqlite3_finalize(stmt);
    if (!row->database || !row->collection || !row->tuple ||
        !row->initial_database || !row->initial_collection)
    {
        row_free(row);
        return catalog_error(error, size, "catalog: out of memory");
    }
    return true;
}

static bool
ensure_work_row(AuditCatalogCache *cache, CatalogRow **rows, size_t *count,
                const CatalogRow *decoded, const AuditCatalogLocator *relation,
                const AuditCatalogTid *tid,
                ssize_t *index, char *error, size_t size)
{
    CatalogRow row = {0};
    CatalogRow *grown;
    *index = decoded ? find_work_row(*rows, *count, decoded->collection_id) : -1;
    if (*index >= 0)
        return true;
    if (!load_committed_row(cache, decoded ? decoded->collection_id : 0,
                            relation,
                            tid, &row, error, size))
        return false;
    if (!row.present && decoded)
    {
        row.collection_id = decoded->collection_id;
        row.relation = decoded->relation;
    }
    grown = realloc(*rows, (*count + 1) * sizeof(*grown));
    if (!grown)
    {
        row_free(&row);
        return catalog_error(error, size, "catalog: out of memory");
    }
    *rows = grown;
    (*rows)[*count] = row;
    *index = (ssize_t)(*count);
    (*count)++;
    return true;
}

static void
replace_current(CatalogRow *target, CatalogRow *source)
{
    free(target->database);
    free(target->collection);
    free(target->tuple);
    target->database = source->database;
    target->collection = source->collection;
    target->tuple = source->tuple;
    target->tuple_length = source->tuple_length;
    target->collection_id = source->collection_id;
    target->is_view = source->is_view;
    target->tid = source->tid;
    target->relation = source->relation;
    target->present = true;
    target->last_lsn = source->last_lsn;
    source->database = source->collection = NULL;
    source->tuple = NULL;
}

static bool
store_row(AuditCatalogCache *cache, const CatalogRow *row,
          char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    char lsn[32];
    if (!row->present)
    {
        if (sqlite3_prepare_v2(cache->db, "DELETE FROM rows WHERE collection_id=?1",
                              -1, &stmt, NULL) != SQLITE_OK)
            return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
        sqlite3_bind_int64(stmt, 1, row->collection_id);
    }
    else
    {
        snprintf(lsn, sizeof(lsn), "%" PRIu64, (uint64)row->last_lsn);
        if (sqlite3_prepare_v2(cache->db,
            "INSERT INTO rows VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) "
            "ON CONFLICT(collection_id) DO UPDATE SET "
            "database_name=excluded.database_name,"
            "collection_name=excluded.collection_name,is_view=excluded.is_view,"
            "tablespace=excluded.tablespace,database_oid=excluded.database_oid,"
            "relfilenode=excluded.relfilenode,block=excluded.block,"
            "offnum=excluded.offnum,tuple=excluded.tuple,last_lsn=excluded.last_lsn",
            -1, &stmt, NULL) != SQLITE_OK)
            return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
        sqlite3_bind_int64(stmt, 1, row->collection_id);
        sqlite3_bind_text(stmt, 2, row->database, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, row->collection, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, row->is_view);
        sqlite3_bind_int64(stmt, 5, row->relation.tablespace);
        sqlite3_bind_int64(stmt, 6, row->relation.database_oid);
        sqlite3_bind_int64(stmt, 7, row->relation.relfilenode);
        sqlite3_bind_int64(stmt, 8, row->tid.block);
        sqlite3_bind_int(stmt, 9, row->tid.offset);
        sqlite3_bind_blob64(stmt, 10, row->tuple, row->tuple_length, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 11, lsn, -1, SQLITE_TRANSIENT);
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_DONE)
        return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
    return true;
}

static bool
commit_transaction(AuditCatalogCache *cache, const AuditCatalogInput *input,
                   AuditCatalogDeltaList *deltas, char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    CatalogRow *rows = NULL;
    size_t row_count = 0;
    int rc;
    bool ok = false;
    char commit_lsn[32];
    XLogRecPtr prior_commit;
    if (cache->config.mode == AUDIT_CATALOG_CACHE_READONLY)
        return catalog_error(error, size, "catalog cache: cannot commit in read-only mode");
    if (!checkpoint_lsn(cache, "commit_lsn", &prior_commit, error, size))
        return false;
    if (input->outcome_lsn <= prior_commit)
        return true;
    if (!exec_sql(cache->db, "BEGIN IMMEDIATE", error, size))
        return false;
    if (sqlite3_prepare_v2(cache->db,
        "SELECT record_lsn,operation,tablespace,database_oid,relfilenode,"
        "old_block,old_offnum,new_block,new_offnum,old_tuple,new_tuple "
        "FROM pending WHERE xid=?1 ORDER BY seq", -1, &stmt, NULL) != SQLITE_OK)
        goto sqlite_fail;
    sqlite3_bind_int64(stmt, 1, input->xid);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        CatalogRow old = {0}, new = {0};
        AuditCatalogTid old_tid = {0}, new_tid = {0};
        AuditCatalogLocator relation;
        AuditCatalogHeapOperation operation = sqlite3_column_int(stmt, 1);
        XLogRecPtr record_lsn = strtoull((const char *)sqlite3_column_text(stmt, 0), NULL, 10);
        ssize_t index = -1;
        relation.tablespace = sqlite3_column_int64(stmt, 2);
        relation.database_oid = sqlite3_column_int64(stmt, 3);
        relation.relfilenode = sqlite3_column_int64(stmt, 4);
        if (sqlite3_column_type(stmt, 5) != SQLITE_NULL)
        {
            old_tid.valid = true;
            old_tid.block = sqlite3_column_int64(stmt, 5);
            old_tid.offset = sqlite3_column_int(stmt, 6);
        }
        if (sqlite3_column_type(stmt, 7) != SQLITE_NULL)
        {
            new_tid.valid = true;
            new_tid.block = sqlite3_column_int64(stmt, 7);
            new_tid.offset = sqlite3_column_int(stmt, 8);
        }
        if (sqlite3_column_type(stmt, 9) != SQLITE_NULL &&
            !decode_tuple(cache, sqlite3_column_blob(stmt, 9),
                          sqlite3_column_bytes(stmt, 9), &old, error, size))
            goto done;
        if (sqlite3_column_type(stmt, 10) != SQLITE_NULL &&
            !decode_tuple(cache, sqlite3_column_blob(stmt, 10),
                          sqlite3_column_bytes(stmt, 10), &new, error, size))
            goto done;
        old.tid = old_tid;
        new.tid = new_tid;
        old.relation = new.relation = relation;
        old.last_lsn = new.last_lsn = record_lsn;
        if (operation == AUDIT_CATALOG_HEAP_INSERT && new.present)
        {
            if (!ensure_work_row(cache, &rows, &row_count, &new, &relation,
                                 &new_tid,
                                 &index, error, size))
                goto done;
            if (rows[index].present)
            {
                CatalogRow unknown = new;
                unknown.initial_present = false;
                if (!append_delta(cache, deltas, AUDIT_CATALOG_UNKNOWN, &unknown,
                                  input->xid, input->outcome_lsn,
                                  "catalog_insert_conflicts_with_state", error, size))
                    goto done;
            }
            else
            {
                new.first_lsn = rows[index].first_lsn ?
                    rows[index].first_lsn : record_lsn;
                replace_current(&rows[index], &new);
                if (!rows[index].first_lsn)
                    rows[index].first_lsn = record_lsn;
            }
        }
        else if (operation == AUDIT_CATALOG_HEAP_UPDATE && new.present)
        {
            const CatalogRow *key = old.present ? &old : &new;
            if (old.present &&
                (old.collection_id != new.collection_id ||
                 strcmp(old.database, new.database)))
            {
                CatalogRow unknown = new;
                unknown.first_lsn = record_lsn;
                if (!append_delta(cache, deltas, AUDIT_CATALOG_UNKNOWN, &unknown,
                                  input->xid, input->outcome_lsn,
                                  "catalog_update_identity_changed", error, size))
                    goto done;
                row_free(&old);
                row_free(&new);
                continue;
            }
            if (!ensure_work_row(cache, &rows, &row_count, key, &relation,
                                 &old_tid,
                                 &index, error, size))
                goto done;
            if (!rows[index].present)
            {
                CatalogRow unknown = new;
                unknown.first_lsn = record_lsn;
                if (!append_delta(cache, deltas, AUDIT_CATALOG_UNKNOWN, &unknown,
                                  input->xid, input->outcome_lsn,
                                  "catalog_update_base_missing", error, size))
                    goto done;
            }
            else if (old.present &&
                     (strcmp(rows[index].database, old.database) ||
                      strcmp(rows[index].collection, old.collection) ||
                      rows[index].is_view != old.is_view))
            {
                CatalogRow unknown = new;
                unknown.first_lsn = record_lsn;
                if (!append_delta(cache, deltas, AUDIT_CATALOG_UNKNOWN, &unknown,
                                  input->xid, input->outcome_lsn,
                                  "catalog_update_base_mismatch", error, size))
                    goto done;
            }
            else
            {
                new.first_lsn = rows[index].first_lsn ?
                    rows[index].first_lsn : record_lsn;
                replace_current(&rows[index], &new);
                if (!rows[index].first_lsn)
                    rows[index].first_lsn = record_lsn;
            }
        }
        else if (operation == AUDIT_CATALOG_HEAP_DELETE)
        {
            const CatalogRow *key = old.present ? &old : NULL;
            if (!ensure_work_row(cache, &rows, &row_count, key, &relation,
                                 &old_tid,
                                 &index, error, size))
                goto done;
            if (!rows[index].present)
            {
                CatalogRow unknown = old;
                unknown.relation = relation;
                unknown.first_lsn = record_lsn;
                if (!append_delta(cache, deltas, AUDIT_CATALOG_UNKNOWN, &unknown,
                                  input->xid, input->outcome_lsn,
                                  "catalog_delete_state_missing", error, size))
                    goto done;
            }
            else
            {
                rows[index].present = false;
                rows[index].last_lsn = record_lsn;
                if (!rows[index].first_lsn)
                    rows[index].first_lsn = record_lsn;
            }
        }
        else
        {
            CatalogRow unknown = old.present ? old : new;
            unknown.relation = relation;
            unknown.first_lsn = record_lsn;
            if (!append_delta(cache, deltas, AUDIT_CATALOG_UNKNOWN, &unknown,
                              input->xid, input->outcome_lsn,
                              "catalog_tuple_unavailable", error, size))
                goto done;
        }
        row_free(&old);
        row_free(&new);
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_DONE)
        goto sqlite_fail;
    for (size_t i = 0; i < deltas->count; i++)
        if (deltas->items[i].operation == AUDIT_CATALOG_UNKNOWN)
        {
            cache->config.coverage = AUDIT_CATALOG_COVERAGE_PARTIAL;
            if (!exec_sql(cache->db,
                          "UPDATE metadata SET value='0' WHERE key='coverage'",
                          error, size))
                goto done;
            break;
        }
    for (size_t i = 0; i < row_count; i++)
    {
        CatalogRow *row = &rows[i];
        AuditCatalogOperation operation = AUDIT_CATALOG_UNKNOWN;
        if (row->initial_present && !row->present)
            operation = row->initial_is_view ?
                AUDIT_CATALOG_VIEW_DROP : AUDIT_CATALOG_COLLECTION_DROP;
        else if (!row->initial_present && row->present)
            operation = row->is_view ?
                AUDIT_CATALOG_VIEW_CREATE : AUDIT_CATALOG_COLLECTION_CREATE;
        else if (row->initial_present && row->present &&
                 (!strcmp(row->initial_database, row->database)) &&
                 strcmp(row->initial_collection, row->collection))
            operation = row->is_view ?
                AUDIT_CATALOG_VIEW_RENAME : AUDIT_CATALOG_COLLECTION_RENAME;
        if (!row->initial_present && row->present &&
            strcmp(row->collection, "system.dbSentinel") != 0 &&
            !has_database_delta(deltas, row->database))
        {
            bool existed = false;
            bool local_sentinel =
                creates_database_sentinel(rows, row_count, row->database);
            if (cache->config.coverage >=
                    AUDIT_CATALOG_COVERAGE_COMPLETE_FROM_CACHE &&
                !database_existed(cache, row->database, &existed, error, size))
                goto done;
            if ((local_sentinel ||
                 (cache->config.coverage >=
                      AUDIT_CATALOG_COVERAGE_COMPLETE_FROM_CACHE && !existed)) &&
                !append_delta(cache, deltas, AUDIT_CATALOG_DATABASE_CREATE, row,
                              input->xid, input->outcome_lsn, NULL, error, size))
                goto done;
        }
        if (operation != AUDIT_CATALOG_UNKNOWN &&
            strcmp(row->collection ? row->collection : "",
                   "system.dbSentinel") != 0 &&
            strcmp(row->initial_collection ? row->initial_collection : "",
                   "system.dbSentinel") != 0 &&
            !append_delta(cache, deltas, operation, row, input->xid,
                          input->outcome_lsn, NULL, error, size))
            goto done;
        if (!store_row(cache, row, error, size))
            goto done;
    }
    qsort(deltas->items, deltas->count, sizeof(*deltas->items), compare_delta);
    if (sqlite3_prepare_v2(cache->db,
        "INSERT INTO ledger SELECT xid,record_lsn,operation_ordinal,operation,"
        "tablespace,database_oid,relfilenode,old_block,old_offnum,new_block,"
        "new_offnum,old_tuple,new_tuple FROM pending WHERE xid=?1",
        -1, &stmt, NULL) != SQLITE_OK)
        goto sqlite_fail;
    sqlite3_bind_int64(stmt, 1, input->xid);
    if (sqlite3_step(stmt) != SQLITE_DONE)
        goto sqlite_fail;
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (sqlite3_prepare_v2(cache->db, "DELETE FROM pending WHERE xid=?1",
                          -1, &stmt, NULL) != SQLITE_OK)
        goto sqlite_fail;
    sqlite3_bind_int64(stmt, 1, input->xid);
    if (sqlite3_step(stmt) != SQLITE_DONE)
        goto sqlite_fail;
    sqlite3_finalize(stmt);
    stmt = NULL;
    snprintf(commit_lsn, sizeof(commit_lsn), "%" PRIu64, (uint64)input->outcome_lsn);
    if (sqlite3_prepare_v2(cache->db,
        "UPDATE checkpoint SET replay_lsn=?1,commit_lsn=?1 WHERE singleton=1",
        -1, &stmt, NULL) != SQLITE_OK)
        goto sqlite_fail;
    sqlite3_bind_text(stmt, 1, commit_lsn, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE)
        goto sqlite_fail;
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (!exec_sql(cache->db, "COMMIT", error, size))
        goto done;
    ok = true;
    goto done;
sqlite_fail:
    catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
done:
    if (stmt)
        sqlite3_finalize(stmt);
    if (!ok)
    {
        sqlite3_exec(cache->db, "ROLLBACK", NULL, NULL, NULL);
        audit_catalog_delta_list_free(deltas);
    }
    for (size_t i = 0; i < row_count; i++)
        row_free(&rows[i]);
    free(rows);
    return ok;
}

static bool
abort_transaction(AuditCatalogCache *cache, TransactionId xid,
                  XLogRecPtr outcome_lsn,
                  char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    char lsn[32];
    if (cache->config.mode == AUDIT_CATALOG_CACHE_READONLY)
        return catalog_error(error, size, "catalog cache: cannot abort in read-only mode");
    XLogRecPtr checkpoint;
    if (!checkpoint_lsn(cache, "replay_lsn", &checkpoint, error, size))
        return false;
    if (outcome_lsn <= checkpoint)
        return true;
    if (!exec_sql(cache->db, "BEGIN IMMEDIATE", error, size))
        return false;
    if (sqlite3_prepare_v2(cache->db, "DELETE FROM pending WHERE xid=?1",
                          -1, &stmt, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_int64(stmt, 1, xid);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_DONE)
        goto fail;
    snprintf(lsn, sizeof(lsn), "%" PRIu64, (uint64)outcome_lsn);
    if (sqlite3_prepare_v2(cache->db,
        "UPDATE checkpoint SET replay_lsn=?1 WHERE singleton=1",
        -1, &stmt, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(stmt, 1, lsn, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc == SQLITE_DONE && exec_sql(cache->db, "COMMIT", error, size))
        return true;
fail:
    if (stmt)
        sqlite3_finalize(stmt);
    sqlite3_exec(cache->db, "ROLLBACK", NULL, NULL, NULL);
    return catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
}

bool
audit_catalog_process(AuditCatalogCache *cache, const AuditCatalogInput *input,
                      AuditCatalogDeltaList *deltas, char *error, size_t size)
{
    if (!cache || !input || !deltas)
        return catalog_error(error, size, "catalog: invalid process request");
    memset(deltas, 0, sizeof(*deltas));
    if (input->outcome == AUDIT_CATALOG_TX_PENDING)
        return stage_mutation(cache, input, error, size);
    if (!input->xid || input->operation != AUDIT_CATALOG_HEAP_NONE)
        return catalog_error(error, size,
                             "catalog: transaction outcome requires XID and no heap operation");
    if (input->outcome == AUDIT_CATALOG_TX_ABORT)
        return abort_transaction(cache, input->xid, input->outcome_lsn,
                                 error, size);
    if (input->outcome == AUDIT_CATALOG_TX_COMMIT)
        return commit_transaction(cache, input, deltas, error, size);
    return catalog_error(error, size, "catalog: invalid transaction outcome");
}

bool
audit_catalog_assign_parent(AuditCatalogCache *cache,
                            TransactionId child, TransactionId parent,
                            char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    if (!cache || !child || !parent || child == parent)
        return catalog_error(error, size,
                             "catalog: invalid subtransaction assignment");
    if (cache->config.mode == AUDIT_CATALOG_CACHE_READONLY)
        return catalog_error(error, size,
                             "catalog cache: cannot reparent in read-only mode");
    if (sqlite3_prepare_v2(cache->db,
        "UPDATE pending SET xid=?1 WHERE xid=?2", -1,
        &stmt, NULL) != SQLITE_OK)
        return catalog_error(error, size, "catalog cache: %s",
                             sqlite3_errmsg(cache->db));
    sqlite3_bind_int64(stmt, 1, parent);
    sqlite3_bind_int64(stmt, 2, child);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? true :
        catalog_error(error, size, "catalog cache: %s", sqlite3_errmsg(cache->db));
}

bool
audit_catalog_cache_publish_rebuild(AuditCatalogCache *cache,
                                    char *error, size_t size)
{
    char *directory = NULL;
    if (!cache || cache->config.mode != AUDIT_CATALOG_CACHE_REBUILD ||
        !cache->active_path || !cache->opened_path)
        return catalog_error(error, size, "catalog cache: not a rebuild candidate");
    if (sqlite3_close(cache->db) != SQLITE_OK)
        return catalog_error(error, size, "catalog cache: cannot close rebuild candidate");
    cache->db = NULL;
    if (rename(cache->opened_path, cache->active_path))
        return catalog_error(error, size, "catalog cache: cannot publish rebuild candidate");
    if (!private_parent(cache->active_path, &directory, error, size))
        return false;
    int fd = open(directory, O_RDONLY);
    if (fd < 0 || fsync(fd) || close(fd))
    {
        if (fd >= 0)
            close(fd);
        free(directory);
        return catalog_error(error, size, "catalog cache: cannot sync containing directory");
    }
    free(directory);
    return true;
}

bool
audit_catalog_cache_mark_gap(AuditCatalogCache *cache, XLogRecPtr gap_lsn,
                             char *error, size_t size)
{
    sqlite3_stmt *stmt = NULL;
    char lsn[32];
    int rc;
    if (!cache || cache->config.mode == AUDIT_CATALOG_CACHE_READONLY)
        return catalog_error(error, size, "catalog cache: cannot mark gap");
    cache->config.coverage = AUDIT_CATALOG_COVERAGE_PARTIAL;
    snprintf(lsn, sizeof(lsn), "%" PRIu64, (uint64)gap_lsn);
    if (!exec_sql(cache->db, "BEGIN IMMEDIATE", error, size))
        return false;
    if (!exec_sql(cache->db,
                  "UPDATE metadata SET value='0' WHERE key='coverage'",
                  error, size))
        goto fail_no_stmt;
    if (sqlite3_prepare_v2(cache->db,
        "UPDATE checkpoint SET replay_lsn=?1 WHERE singleton=1",
        -1, &stmt, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(stmt, 1, lsn, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_DONE || !exec_sql(cache->db, "COMMIT", error, size))
        goto fail_no_stmt;
    return true;
fail:
    if (stmt)
        sqlite3_finalize(stmt);
fail_no_stmt:
    sqlite3_exec(cache->db, "ROLLBACK", NULL, NULL, NULL);
    return catalog_error(error, size, "catalog cache: cannot persist WAL gap");
}

bool
audit_catalog_cache_delete(const char *path, char *error, size_t size)
{
    char *directory = NULL;
    struct stat st;
    if (!private_parent(path, &directory, error, size))
        return false;
    free(directory);
    if (lstat(path, &st))
        return errno == ENOENT ? true :
            catalog_error(error, size, "catalog cache: cannot inspect cache file");
    if (!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0777) != 0600)
        return catalog_error(error, size, "catalog cache: unsafe cache file");
    return unlink(path) == 0 ? true :
        catalog_error(error, size, "catalog cache: cannot delete cache file");
}

void
audit_catalog_delta_list_free(AuditCatalogDeltaList *deltas)
{
    if (!deltas)
        return;
    for (size_t i = 0; i < deltas->count; i++)
    {
        free(deltas->items[i].before_database);
        free(deltas->items[i].before_collection);
        free(deltas->items[i].after_database);
        free(deltas->items[i].after_collection);
    }
    free(deltas->items);
    memset(deltas, 0, sizeof(*deltas));
}

void
audit_catalog_cache_close(AuditCatalogCache *cache)
{
    if (!cache)
        return;
    if (cache->db)
        sqlite3_close(cache->db);
    free(cache->active_path);
    free(cache->opened_path);
    free(cache);
}

const char *
audit_catalog_operation_name(AuditCatalogOperation operation)
{
    switch (operation)
    {
        case AUDIT_CATALOG_DATABASE_CREATE: return "databaseCreate";
        case AUDIT_CATALOG_COLLECTION_CREATE: return "collectionCreate";
        case AUDIT_CATALOG_VIEW_CREATE: return "viewCreate";
        case AUDIT_CATALOG_COLLECTION_RENAME: return "collectionRename";
        case AUDIT_CATALOG_VIEW_RENAME: return "viewRename";
        case AUDIT_CATALOG_COLLECTION_DROP: return "collectionDrop";
        case AUDIT_CATALOG_VIEW_DROP: return "viewDrop";
        default: return "unknown";
    }
}

static void
    bind_page_relation(sqlite3_stmt *stmt, int first,
                       const AuditRelationGeneration *relation)
    {
        sqlite3_bind_int64(stmt, first, relation->tablespace);
        sqlite3_bind_int64(stmt, first + 1, relation->database_oid);
        sqlite3_bind_int64(stmt, first + 2, relation->relfilenode);
        sqlite3_bind_int(stmt, first + 3, relation->fork_number);
        sqlite3_bind_int64(stmt, first + 4, (sqlite3_int64)relation->generation);
    }

    static bool
    page_write_allowed(AuditCatalogCache *cache, char *error, size_t size)
    {
        return cache && cache->db &&
            (cache->config.mode != AUDIT_CATALOG_CACHE_READONLY ||
             catalog_error(error, size,
                           "catalog cache: page state is read-only"));
    }

    static bool
    page_relation_lifecycle(void *context,
                            const AuditRelationGeneration *relation,
                            XLogRecPtr lsn, int lifecycle,
                            char *error, size_t size)
    {
        AuditCatalogCache *cache = context;
        sqlite3_stmt *stmt = NULL;
        char lsn_text[32];
        int rc;
        if (!page_write_allowed(cache, error, size))
            return false;
        snprintf(lsn_text, sizeof(lsn_text), "%" PRIu64, (uint64)lsn);
        if (sqlite3_prepare_v2(cache->db,
            "INSERT INTO page_relations VALUES(?1,?2,?3,?4,?5,?6,?7) "
            "ON CONFLICT DO NOTHING", -1, &stmt, NULL) != SQLITE_OK)
            return catalog_error(error, size, "catalog cache: %s",
                                 sqlite3_errmsg(cache->db));
        bind_page_relation(stmt, 1, relation);
        sqlite3_bind_int(stmt, 6, lifecycle);
        sqlite3_bind_text(stmt, 7, lsn_text, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE || catalog_error(error, size, "catalog cache: %s",
                                                   sqlite3_errmsg(cache->db));
    }

    static bool
    page_relation_create(void *context,
                         const AuditRelationGeneration *relation,
                         XLogRecPtr lsn, char *error, size_t size)
    {
        return page_relation_lifecycle(context, relation, lsn, 1, error, size);
    }

    static bool
    page_relation_close(void *context,
                        const AuditRelationGeneration *relation,
                        XLogRecPtr lsn, char *error, size_t size)
    {
        return page_relation_lifecycle(context, relation, lsn, 2, error, size);
    }

    static bool
    page_store_tuple(void *context,
                     const AuditRelationGeneration *relation,
                     AuditPhysicalTid tid, const AuditTupleState *tuple,
                     char *error, size_t size)
    {
        AuditCatalogCache *cache = context;
        sqlite3_stmt *stmt = NULL;
        char lsn_text[32];
        int rc;
        if (!page_write_allowed(cache, error, size))
            return false;
        snprintf(lsn_text, sizeof(lsn_text), "%" PRIu64,
                 (uint64)tuple->applied_lsn);
        if (sqlite3_prepare_v2(cache->db,
            "INSERT INTO page_tuples VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) "
            "ON CONFLICT DO NOTHING", -1, &stmt, NULL) != SQLITE_OK)
            return catalog_error(error, size, "catalog cache: %s",
                                 sqlite3_errmsg(cache->db));
        bind_page_relation(stmt, 1, relation);
        sqlite3_bind_int64(stmt, 6, tid.block);
        sqlite3_bind_int(stmt, 7, tid.offset);
        if (tuple->data && tuple->length)
            sqlite3_bind_blob64(stmt, 8, tuple->data, tuple->length,
                                SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 9, tuple->slot_state);
        sqlite3_bind_int(stmt, 10, tuple->trust);
        sqlite3_bind_int(stmt, 11, tuple->source);
        sqlite3_bind_text(stmt, 12, lsn_text, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE || catalog_error(error, size, "catalog cache: %s",
                                                   sqlite3_errmsg(cache->db));
    }

    static bool
    page_load_tuple(void *context,
                    const AuditRelationGeneration *relation,
                    AuditPhysicalTid tid, XLogRecPtr before_lsn,
                    AuditTupleState *tuple, char *error, size_t size)
    {
        AuditCatalogCache *cache = context;
        sqlite3_stmt *stmt = NULL;
        char before[32];
        int rc;
        snprintf(before, sizeof(before), "%" PRIu64, (uint64)before_lsn);
        if (sqlite3_prepare_v2(cache->db,
            "SELECT tuple,slot_state,trust,source,applied_lsn FROM page_tuples "
            "WHERE tablespace=?1 AND database_oid=?2 AND relfilenode=?3 AND fork=?4 "
            "AND generation=?5 AND block=?6 AND offnum=?7 "
            "AND CAST(applied_lsn AS INTEGER)<CAST(?8 AS INTEGER) "
            "ORDER BY CAST(applied_lsn AS INTEGER) DESC LIMIT 1",
            -1, &stmt, NULL) != SQLITE_OK)
            return catalog_error(error, size, "catalog cache: %s",
                                 sqlite3_errmsg(cache->db));
        bind_page_relation(stmt, 1, relation);
        sqlite3_bind_int64(stmt, 6, tid.block);
        sqlite3_bind_int(stmt, 7, tid.offset);
        sqlite3_bind_text(stmt, 8, before, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW)
        {
            tuple->present = true;
            tuple->slot_state = sqlite3_column_int(stmt, 1);
            tuple->trust = sqlite3_column_int(stmt, 2);
            tuple->source = sqlite3_column_int(stmt, 3);
            tuple->applied_lsn =
                strtoull((const char *)sqlite3_column_text(stmt, 4), NULL, 10);
            if (sqlite3_column_type(stmt, 0) == SQLITE_BLOB)
            {
                tuple->length = sqlite3_column_bytes(stmt, 0);
                tuple->data = malloc(tuple->length);
                if (!tuple->data)
                {
                    sqlite3_finalize(stmt);
                    return catalog_error(error, size,
                                         "catalog cache: out of memory");
                }
                memcpy(tuple->data, sqlite3_column_blob(stmt, 0), tuple->length);
            }
        }
        sqlite3_finalize(stmt);
        if (rc != SQLITE_ROW && rc != SQLITE_DONE)
            return catalog_error(error, size, "catalog cache: %s",
                                 sqlite3_errmsg(cache->db));
        if (!tuple->present)
            return true;

        if (sqlite3_prepare_v2(cache->db,
            "SELECT MAX(CAST(applied_lsn AS INTEGER)) FROM page_invalidations "
            "WHERE CAST(applied_lsn AS INTEGER)<CAST(?1 AS INTEGER) AND "
            "(scope=2 OR (scope=1 AND tablespace=?2 AND database_oid=?3 AND "
            "relfilenode=?4 AND fork=?5 AND generation=?6 AND block=?7))",
            -1, &stmt, NULL) != SQLITE_OK)
            return catalog_error(error, size, "catalog cache: %s",
                                 sqlite3_errmsg(cache->db));
        sqlite3_bind_text(stmt, 1, before, -1, SQLITE_TRANSIENT);
        bind_page_relation(stmt, 2, relation);
        sqlite3_bind_int64(stmt, 7, tid.block);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL &&
            (XLogRecPtr)sqlite3_column_int64(stmt, 0) > tuple->applied_lsn)
            tuple->trust = AUDIT_PAGE_UNTRUSTED;
        sqlite3_finalize(stmt);
        return rc == SQLITE_ROW || catalog_error(error, size, "catalog cache: %s",
                                                  sqlite3_errmsg(cache->db));
    }

    static bool
    page_set_slot_state(void *context,
                        const AuditRelationGeneration *relation,
                        AuditPhysicalTid tid, AuditSlotState state,
                        XLogRecPtr lsn, char *error, size_t size)
    {
        AuditTupleState old = {0};
        if (!page_load_tuple(context, relation, tid, lsn, &old, error, size))
            return false;
        AuditTupleState value = {
            .data = old.data,
            .length = old.length,
            .present = true,
            .slot_state = state,
            .trust = old.present ? old.trust : AUDIT_PAGE_UNTRUSTED,
            .source = old.present ? old.source : AUDIT_STATE_SOURCE_WAL_TUPLE,
            .applied_lsn = lsn
        };
        bool ok = page_store_tuple(context, relation, tid, &value, error, size);
        free(old.data);
        return ok;
    }

    static bool
    page_apply_update(void *context,
                      const AuditRelationGeneration *old_relation,
                      AuditPhysicalTid old_tid,
                      const AuditRelationGeneration *new_relation,
                      AuditPhysicalTid new_tid,
                      const AuditTupleState *new_tuple, XLogRecPtr lsn,
                      char *error, size_t size)
    {
        AuditCatalogCache *cache = context;
        bool ok = false;
        if (!page_write_allowed(cache, error, size) ||
            !exec_sql(cache->db, "BEGIN IMMEDIATE", error, size))
            return false;
        if (page_set_slot_state(context, old_relation, old_tid,
                                AUDIT_SLOT_NOT_NORMAL, lsn, error, size) &&
            page_store_tuple(context, new_relation, new_tid, new_tuple,
                             error, size) &&
            exec_sql(cache->db, "COMMIT", error, size))
            ok = true;
        if (!ok)
            exec_sql(cache->db, "ROLLBACK", error, size);
        return ok;
    }

    static bool
    page_replace(void *context,
                 const AuditRelationGeneration *relation, uint32 block,
                 const AuditPageTuple *tuples, size_t tuple_count,
                 AuditPageTrust trust, AuditPageStateSource source,
                 XLogRecPtr lsn, char *error, size_t size)
    {
        AuditCatalogCache *cache = context;
        sqlite3_stmt *stmt = NULL;
        char lsn_text[32];
        int rc;
        if (!page_write_allowed(cache, error, size) ||
            !exec_sql(cache->db, "BEGIN IMMEDIATE", error, size))
            return false;
        snprintf(lsn_text, sizeof(lsn_text), "%" PRIu64, (uint64)lsn);
        if (sqlite3_prepare_v2(cache->db,
            "SELECT DISTINCT offnum FROM page_tuples p WHERE tablespace=?1 AND "
            "database_oid=?2 AND relfilenode=?3 AND fork=?4 AND generation=?5 "
            "AND block=?6 AND applied_lsn=(SELECT applied_lsn FROM page_tuples q "
            "WHERE q.tablespace=p.tablespace AND q.database_oid=p.database_oid "
            "AND q.relfilenode=p.relfilenode AND q.fork=p.fork "
            "AND q.generation=p.generation AND q.block=p.block AND q.offnum=p.offnum "
            "AND CAST(q.applied_lsn AS INTEGER)<CAST(?7 AS INTEGER) "
            "ORDER BY CAST(q.applied_lsn AS INTEGER) DESC LIMIT 1)",
            -1, &stmt, NULL) != SQLITE_OK)
            goto fail;
        bind_page_relation(stmt, 1, relation);
        sqlite3_bind_int64(stmt, 6, block);
        sqlite3_bind_text(stmt, 7, lsn_text, -1, SQLITE_TRANSIENT);
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
        {
            uint16 offset = sqlite3_column_int(stmt, 0);
            bool found = false;
            for (size_t i = 0; i < tuple_count; i++)
                if (tuples[i].offset == offset)
                {
                    found = true;
                    break;
                }
            if (!found)
            {
                AuditTupleState absent = {
                    .present = true,
                    .slot_state = AUDIT_SLOT_NOT_NORMAL,
                    .trust = trust,
                    .source = source,
                    .applied_lsn = lsn
                };
                AuditPhysicalTid tid = {block, offset};
                if (!page_store_tuple(context, relation, tid, &absent,
                                      error, size))
                {
                    sqlite3_finalize(stmt);
                    goto fail;
                }
            }
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
        if (rc != SQLITE_DONE)
            goto fail;
        for (size_t i = 0; i < tuple_count; i++)
        {
            AuditTupleState value = {
                .data = (uint8 *)tuples[i].data,
                .length = tuples[i].length,
                .present = true,
                .slot_state = tuples[i].slot_state,
                .trust = trust,
                .source = source,
                .applied_lsn = lsn
            };
            AuditPhysicalTid tid = {block, tuples[i].offset};
            if (!page_store_tuple(context, relation, tid, &value, error, size))
                goto fail;
        }
        if (exec_sql(cache->db, "COMMIT", error, size))
            return true;
    fail:
        if (stmt)
            sqlite3_finalize(stmt);
        exec_sql(cache->db, "ROLLBACK", error, size);
        return false;
    }

    static bool
    page_truncate(void *context,
                  const AuditRelationGeneration *relation,
                  uint32 first_removed_block, XLogRecPtr lsn,
                  char *error, size_t size)
    {
        AuditCatalogCache *cache = context;
        sqlite3_stmt *stmt = NULL;
        char lsn_text[32];
        int rc;
        if (!page_write_allowed(cache, error, size))
            return false;
        snprintf(lsn_text, sizeof(lsn_text), "%" PRIu64, (uint64)lsn);
        if (sqlite3_prepare_v2(cache->db,
            "INSERT OR IGNORE INTO page_tuples "
            "SELECT tablespace,database_oid,relfilenode,fork,generation,block,offnum,"
            "NULL,?1,?2,?3,?4 FROM page_tuples p WHERE tablespace=?5 AND "
            "database_oid=?6 AND relfilenode=?7 AND fork=?8 AND generation=?9 "
            "AND block>=?10 AND applied_lsn=(SELECT applied_lsn FROM page_tuples q "
            "WHERE q.tablespace=p.tablespace AND q.database_oid=p.database_oid "
            "AND q.relfilenode=p.relfilenode AND q.fork=p.fork "
            "AND q.generation=p.generation AND q.block=p.block AND q.offnum=p.offnum "
            "AND CAST(q.applied_lsn AS INTEGER)<CAST(?4 AS INTEGER) "
            "ORDER BY CAST(q.applied_lsn AS INTEGER) DESC LIMIT 1)",
            -1, &stmt, NULL) != SQLITE_OK)
            return catalog_error(error, size, "catalog cache: %s",
                                 sqlite3_errmsg(cache->db));
        sqlite3_bind_int(stmt, 1, AUDIT_SLOT_NOT_NORMAL);
        sqlite3_bind_int(stmt, 2, AUDIT_PAGE_UNTRUSTED);
        sqlite3_bind_int(stmt, 3, AUDIT_STATE_SOURCE_WAL_TUPLE);
        sqlite3_bind_text(stmt, 4, lsn_text, -1, SQLITE_TRANSIENT);
        bind_page_relation(stmt, 5, relation);
        sqlite3_bind_int64(stmt, 10, first_removed_block);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE || catalog_error(error, size, "catalog cache: %s",
                                                   sqlite3_errmsg(cache->db));
    }

    static bool
    page_invalidate(void *context,
                    const AuditRelationGeneration *relation, uint32 block,
                    XLogRecPtr lsn, char *error, size_t size)
    {
        AuditCatalogCache *cache = context;
        sqlite3_stmt *stmt = NULL;
        char lsn_text[32];
        int rc;
        if (!page_write_allowed(cache, error, size))
            return false;
        snprintf(lsn_text, sizeof(lsn_text), "%" PRIu64, (uint64)lsn);
        if (sqlite3_prepare_v2(cache->db,
            "INSERT OR IGNORE INTO page_invalidations "
            "VALUES(1,?1,?2,?3,?4,?5,?6,?7)", -1, &stmt, NULL) != SQLITE_OK)
            return catalog_error(error, size, "catalog cache: %s",
                                 sqlite3_errmsg(cache->db));
        bind_page_relation(stmt, 1, relation);
        sqlite3_bind_int64(stmt, 6, block);
        sqlite3_bind_text(stmt, 7, lsn_text, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE || catalog_error(error, size, "catalog cache: %s",
                                                   sqlite3_errmsg(cache->db));
    }

    static bool
    page_invalidate_all(void *context, XLogRecPtr lsn,
                        char *error, size_t size)
    {
        AuditCatalogCache *cache = context;
        sqlite3_stmt *stmt = NULL;
        char lsn_text[32];
        int rc;
        if (!page_write_allowed(cache, error, size))
            return false;
        snprintf(lsn_text, sizeof(lsn_text), "%" PRIu64, (uint64)lsn);
        if (sqlite3_prepare_v2(cache->db,
            "INSERT OR IGNORE INTO page_invalidations(scope,applied_lsn) "
            "VALUES(2,?1)", -1, &stmt, NULL) != SQLITE_OK)
            return catalog_error(error, size, "catalog cache: %s",
                                 sqlite3_errmsg(cache->db));
        sqlite3_bind_text(stmt, 1, lsn_text, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE || catalog_error(error, size, "catalog cache: %s",
                                                   sqlite3_errmsg(cache->db));
    }

    static void
    page_release_tuple(void *context, AuditTupleState *tuple)
    {
        free(tuple->data);
    }

    bool
    audit_catalog_page_state_backend(AuditCatalogCache *cache,
                                     AuditPageStateBackend *backend,
                                     char *error, size_t size)
    {
        if (!cache || !backend)
            return catalog_error(error, size,
                                 "catalog cache: invalid page-state backend request");
        *backend = (AuditPageStateBackend){
            .context = cache,
            .relation_create = page_relation_create,
            .relation_close = page_relation_close,
            .load_tuple = page_load_tuple,
            .store_tuple = page_store_tuple,
            .set_slot_state = page_set_slot_state,
            .apply_heap_update = page_apply_update,
            .replace_page = page_replace,
            .truncate_relation = page_truncate,
            .invalidate_page = page_invalidate,
            .invalidate_all = page_invalidate_all,
            .release_tuple = page_release_tuple
        };
    return true;
}
