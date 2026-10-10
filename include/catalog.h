#ifndef DOCUMENTDB_WAL_AUDIT_CATALOG_H
#define DOCUMENTDB_WAL_AUDIT_CATALOG_H

#include "audit.h"
#include "page_state.h"

typedef struct AuditCatalogCache AuditCatalogCache;

typedef enum AuditRelationKind
{
    AUDIT_RELATION_DOCUMENT = 1,
    AUDIT_RELATION_COLLECTIONS_CATALOG = 2
} AuditRelationKind;

typedef enum AuditCatalogCoverage
{
    AUDIT_CATALOG_COVERAGE_PARTIAL = 0,
    AUDIT_CATALOG_COVERAGE_ROW_LOCAL,
    AUDIT_CATALOG_COVERAGE_COMPLETE_FROM_CACHE,
    AUDIT_CATALOG_COVERAGE_COMPLETE_FROM_ORIGIN
} AuditCatalogCoverage;

typedef enum AuditCatalogCacheMode
{
    AUDIT_CATALOG_CACHE_NORMAL = 0,
    AUDIT_CATALOG_CACHE_READONLY,
    AUDIT_CATALOG_CACHE_REBUILD,
    AUDIT_CATALOG_CACHE_EPHEMERAL
} AuditCatalogCacheMode;

typedef enum AuditCatalogHeapOperation
{
    AUDIT_CATALOG_HEAP_NONE = 0,
    AUDIT_CATALOG_HEAP_INSERT,
    AUDIT_CATALOG_HEAP_UPDATE,
    AUDIT_CATALOG_HEAP_DELETE
} AuditCatalogHeapOperation;

typedef enum AuditCatalogTransactionOutcome
{
    AUDIT_CATALOG_TX_PENDING = 0,
    AUDIT_CATALOG_TX_COMMIT,
    AUDIT_CATALOG_TX_ABORT
} AuditCatalogTransactionOutcome;

typedef enum AuditCatalogOperation
{
    AUDIT_CATALOG_UNKNOWN = 0,
    AUDIT_CATALOG_DATABASE_CREATE,
    AUDIT_CATALOG_COLLECTION_CREATE,
    AUDIT_CATALOG_VIEW_CREATE,
    AUDIT_CATALOG_COLLECTION_RENAME,
    AUDIT_CATALOG_VIEW_RENAME,
    AUDIT_CATALOG_COLLECTION_DROP,
    AUDIT_CATALOG_VIEW_DROP
} AuditCatalogOperation;

typedef struct AuditCatalogLocator
{
    uint32 tablespace;
    uint32 database_oid;
    uint32 relfilenode;
} AuditCatalogLocator;

typedef struct AuditCatalogTid
{
    uint32 block;
    uint16 offset;
    bool valid;
} AuditCatalogTid;

typedef struct AuditCatalogCacheConfig
{
    const char *path;
    AuditCatalogCacheMode mode;
    AuditCatalogCoverage coverage;
    uint64 system_identifier;
    uint32 postgres_major;
    uint32 block_size;
    uint32 wal_segment_size;
    TimeLineID timeline;
    const char *documentdb_version;
} AuditCatalogCacheConfig;

typedef struct AuditCatalogInput
{
    AuditCatalogLocator relation;
    AuditCatalogHeapOperation operation;
    AuditCatalogTransactionOutcome outcome;
    TransactionId xid;
    XLogRecPtr record_lsn;
    XLogRecPtr outcome_lsn;
    uint32 operation_ordinal;
    AuditCatalogTid old_tid;
    AuditCatalogTid new_tid;
    const uint8 *old_tuple;
    size_t old_tuple_length;
    const uint8 *new_tuple;
    size_t new_tuple_length;
} AuditCatalogInput;

typedef struct AuditCatalogDelta
{
    AuditCatalogOperation operation;
    const char *certainty;
    const char *coverage;
    const char *warning;
    AuditCatalogLocator relation;
    TransactionId xid;
    XLogRecPtr event_lsn;
    XLogRecPtr commit_lsn;
    int64 collection_id;
    bool is_view;
    const char *descriptor_fingerprint;
    const char *evidence;
    char *before_database;
    char *before_collection;
    char *after_database;
    char *after_collection;
} AuditCatalogDelta;

typedef struct AuditCatalogDeltaList
{
    AuditCatalogDelta *items;
    size_t count;
} AuditCatalogDeltaList;

bool audit_catalog_descriptor(const char *documentdb_version,
                              unsigned *attribute_count,
                              const char **fingerprint,
                              char *error, size_t error_size);
AuditCatalogCache *audit_catalog_cache_open(const AuditCatalogCacheConfig *config,
                                            char *error, size_t error_size);
bool audit_catalog_process(AuditCatalogCache *cache,
                           const AuditCatalogInput *input,
                           AuditCatalogDeltaList *deltas,
                           char *error, size_t error_size);
bool audit_catalog_assign_parent(AuditCatalogCache *cache,
                                 TransactionId child, TransactionId parent,
                                 char *error, size_t error_size);
bool audit_catalog_cache_publish_rebuild(AuditCatalogCache *cache,
                                         char *error, size_t error_size);
bool audit_catalog_cache_mark_gap(AuditCatalogCache *cache, XLogRecPtr gap_lsn,
                                  char *error, size_t error_size);
bool audit_catalog_cache_delete(const char *path,
                                char *error, size_t error_size);
bool audit_catalog_page_state_backend(AuditCatalogCache *cache,
                                      AuditPageStateBackend *backend,
                                      char *error, size_t error_size);
void audit_catalog_delta_list_free(AuditCatalogDeltaList *deltas);
void audit_catalog_cache_close(AuditCatalogCache *cache);
const char *audit_catalog_operation_name(AuditCatalogOperation operation);

#endif
