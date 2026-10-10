#ifndef AUDIT_PRIVATE_H
#define AUDIT_PRIVATE_H
#include "audit.h"
#include "catalog.h"
#include <bson/bson.h>

typedef struct AuditRelation
{
    uint32 tablespace, database_oid, relfilenode;
    AuditRelationKind kind;
    int64 collection_id;
    char *database, *collection;
} AuditRelation;

typedef struct AuditManifest
{
    uint64 system_identifier;
    uint32 timeline;
    XLogRecPtr from, to;
    unsigned schema_version;
    char *documentdb_version;
    AuditRelation *relations;
    size_t count;
} AuditManifest;

bool audit_manifest_load(const char *path, AuditManifest *manifest,
                         char *error, size_t error_size);
void audit_manifest_free(AuditManifest *manifest);
const AuditRelation *audit_manifest_relation(const AuditManifest *manifest,
                    uint32 tablespace, uint32 database, uint32 relfilenode,
                    XLogRecPtr lsn);
bool audit_tuple_decode(const uint8 *data, size_t length, uint64 limit,
                        bson_t *object_id, bson_t *document,
                        char *error, size_t error_size);
bool audit_tuple_key_decode(const uint8 *data, size_t length, uint64 limit,
                            bson_t *object_id, char *error, size_t error_size);
#endif
