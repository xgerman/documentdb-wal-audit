#ifndef DOCUMENTDB_WAL_AUDIT_PAGE_STATE_H
#define DOCUMENTDB_WAL_AUDIT_PAGE_STATE_H

#include "postgres_fe.h"
#include "access/xlogdefs.h"

typedef struct AuditPageState AuditPageState;

typedef struct AuditRelationGeneration
{
    uint32 tablespace;
    uint32 database_oid;
    uint32 relfilenode;
    uint8 fork_number;
    uint64 generation;
} AuditRelationGeneration;

typedef struct AuditPhysicalTid
{
    uint32 block;
    uint16 offset;
} AuditPhysicalTid;

typedef enum AuditPageTrust
{
    AUDIT_PAGE_UNTRUSTED = 0,
    AUDIT_PAGE_IMAGE_PROVED,
    AUDIT_PAGE_ORIGIN_PROVED
} AuditPageTrust;

typedef enum AuditSlotState
{
    AUDIT_SLOT_UNUSED = 0,
    AUDIT_SLOT_NORMAL,
    AUDIT_SLOT_NOT_NORMAL
} AuditSlotState;

typedef enum AuditPageStateSource
{
    AUDIT_STATE_SOURCE_WAL_TUPLE = 1,
    AUDIT_STATE_SOURCE_FULL_PAGE_IMAGE,
    AUDIT_STATE_SOURCE_INIT_PAGE
} AuditPageStateSource;

typedef struct AuditTupleState
{
    uint8 *data;
    size_t length;
    bool present;
    AuditSlotState slot_state;
    AuditPageTrust trust;
    AuditPageStateSource source;
    XLogRecPtr applied_lsn;
} AuditTupleState;

typedef struct AuditPageTuple
{
    uint16 offset;
    const uint8 *data;
    size_t length;
    AuditSlotState slot_state;
} AuditPageTuple;

/*
 * Storage implementations contain backup-sensitive tuple bytes and must
 * provide their own durable, owner-only transaction semantics.  A successful
 * callback means the mutation is persistent.  No in-memory fallback exists.
 */
typedef struct AuditPageStateBackend
{
    void *context;
    bool (*relation_create)(void *context,
                            const AuditRelationGeneration *relation,
                            XLogRecPtr lsn, char *error, size_t error_size);
    bool (*relation_close)(void *context,
                           const AuditRelationGeneration *relation,
                           XLogRecPtr lsn, char *error, size_t error_size);
    bool (*load_tuple)(void *context,
                       const AuditRelationGeneration *relation,
                       AuditPhysicalTid tid, XLogRecPtr before_lsn,
                       AuditTupleState *tuple,
                       char *error, size_t error_size);
    bool (*store_tuple)(void *context,
                        const AuditRelationGeneration *relation,
                        AuditPhysicalTid tid, const AuditTupleState *tuple,
                        char *error, size_t error_size);
    bool (*set_slot_state)(void *context,
                           const AuditRelationGeneration *relation,
                           AuditPhysicalTid tid, AuditSlotState state,
                           XLogRecPtr lsn, char *error, size_t error_size);
    bool (*apply_heap_update)(void *context,
                              const AuditRelationGeneration *old_relation,
                              AuditPhysicalTid old_tid,
                              const AuditRelationGeneration *new_relation,
                              AuditPhysicalTid new_tid,
                              const AuditTupleState *new_tuple,
                              XLogRecPtr lsn, char *error, size_t error_size);
    bool (*replace_page)(void *context,
                         const AuditRelationGeneration *relation,
                         uint32 block, const AuditPageTuple *tuples,
                         size_t tuple_count, AuditPageTrust trust,
                         AuditPageStateSource source, XLogRecPtr lsn,
                         char *error, size_t error_size);
    bool (*truncate_relation)(void *context,
                              const AuditRelationGeneration *relation,
                              uint32 first_removed_block, XLogRecPtr lsn,
                              char *error, size_t error_size);
    bool (*invalidate_page)(void *context,
                            const AuditRelationGeneration *relation,
                            uint32 block, XLogRecPtr lsn,
                            char *error, size_t error_size);
    bool (*invalidate_all)(void *context, XLogRecPtr lsn,
                           char *error, size_t error_size);
    void (*release_tuple)(void *context, AuditTupleState *tuple);
} AuditPageStateBackend;

typedef struct AuditPageStateConfig
{
    size_t max_tuple_bytes;
    uint32 max_offset_number;
} AuditPageStateConfig;

AuditPageState *audit_page_state_create(const AuditPageStateConfig *config,
                                        const AuditPageStateBackend *backend,
                                        char *error, size_t error_size);
void audit_page_state_destroy(AuditPageState *state);

bool audit_page_state_relation_create(AuditPageState *state,
                                      const AuditRelationGeneration *relation,
                                      XLogRecPtr lsn,
                                      char *error, size_t error_size);
bool audit_page_state_relation_close(AuditPageState *state,
                                     const AuditRelationGeneration *relation,
                                     XLogRecPtr lsn,
                                     char *error, size_t error_size);
bool audit_page_state_apply_fpi(AuditPageState *state,
                                const AuditRelationGeneration *relation,
                                uint32 block, const AuditPageTuple *tuples,
                                size_t tuple_count, AuditPageTrust trust,
                                AuditPageStateSource source, XLogRecPtr lsn,
                                char *error, size_t error_size);
bool audit_page_state_heap_insert(AuditPageState *state,
                                  const AuditRelationGeneration *relation,
                                  AuditPhysicalTid tid, const uint8 *tuple,
                                  size_t tuple_length, AuditPageTrust trust,
                                  AuditPageStateSource source, XLogRecPtr lsn,
                                  char *error, size_t error_size);
bool audit_page_state_heap_delete(AuditPageState *state,
                                  const AuditRelationGeneration *relation,
                                  AuditPhysicalTid tid, XLogRecPtr lsn,
                                  char *error, size_t error_size);
bool audit_page_state_heap_update(AuditPageState *state,
                                  const AuditRelationGeneration *old_relation,
                                  AuditPhysicalTid old_tid,
                                  const AuditRelationGeneration *new_relation,
                                  AuditPhysicalTid new_tid,
                                  const uint8 *new_tuple,
                                  size_t new_tuple_length,
                                  AuditPageTrust trust, XLogRecPtr lsn,
                                  char *error, size_t error_size);
bool audit_page_state_truncate(AuditPageState *state,
                               const AuditRelationGeneration *relation,
                               uint32 first_removed_block, XLogRecPtr lsn,
                               char *error, size_t error_size);
bool audit_page_state_mark_page_untrusted(AuditPageState *state,
                                          const AuditRelationGeneration *relation,
                                          uint32 block, XLogRecPtr lsn,
                                          char *error, size_t error_size);
bool audit_page_state_mark_gap(AuditPageState *state, XLogRecPtr lsn,
                               char *error, size_t error_size);
bool audit_page_state_load_tuple(AuditPageState *state,
                                 const AuditRelationGeneration *relation,
                                 AuditPhysicalTid tid, XLogRecPtr before_lsn,
                                 AuditTupleState *tuple,
                                 char *error, size_t error_size);
void audit_page_state_release_tuple(AuditPageState *state,
                                    AuditTupleState *tuple);
bool audit_page_image_item_valid(uint16 page_upper, uint16 page_special,
                                 uint16 item_offset, uint16 item_length,
                                 size_t minimum_tuple_length);

#endif
