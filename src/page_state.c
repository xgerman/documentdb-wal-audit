#include "postgres.h"
#include "page_state.h"
#include "access/htup_details.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

struct AuditPageState
{
    AuditPageStateConfig config;
    AuditPageStateBackend backend;
};

bool
audit_page_image_item_valid(uint16 page_upper, uint16 page_special,
                            uint16 item_offset, uint16 item_length,
                            size_t minimum_tuple_length)
{
    return item_length >= minimum_tuple_length &&
           item_offset >= page_upper &&
           item_offset <= page_special &&
           item_length <= (size_t)page_special - item_offset;
}

static bool
state_error(char *error, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(error, size, format, args);
    va_end(args);
    return false;
}

static bool
valid_relation(const AuditRelationGeneration *relation)
{
    return relation && relation->relfilenode != 0 && relation->generation != 0;
}

static bool
valid_tid(const AuditPageState *state, AuditPhysicalTid tid)
{
    return tid.offset > 0 && tid.offset <= state->config.max_offset_number;
}

static bool
valid_tuple(const AuditPageState *state, const uint8 *tuple, size_t length)
{
    const HeapTupleHeaderData *header;
    if (!tuple || length < SizeofHeapTupleHeader ||
        length > state->config.max_tuple_bytes)
        return false;
    header = (const HeapTupleHeaderData *)tuple;
    return header->t_hoff >= SizeofHeapTupleHeader &&
           header->t_hoff <= length;
}

AuditPageState *
audit_page_state_create(const AuditPageStateConfig *config,
                        const AuditPageStateBackend *backend,
                        char *error, size_t size)
{
    AuditPageState *state;
    if (!config || !backend || config->max_tuple_bytes < SizeofHeapTupleHeader ||
        config->max_offset_number == 0 || !backend->relation_create ||
        !backend->relation_close || !backend->load_tuple ||
        !backend->store_tuple || !backend->set_slot_state ||
        !backend->apply_heap_update ||
        !backend->replace_page || !backend->truncate_relation ||
        !backend->invalidate_page || !backend->invalidate_all ||
        !backend->release_tuple)
    {
        state_error(error, size,
                    "page-state: persistent backend and valid limits are required");
        return NULL;
    }
    state = calloc(1, sizeof(*state));
    if (!state)
    {
        state_error(error, size, "page-state: out of memory");
        return NULL;
    }
    state->config = *config;
    state->backend = *backend;
    return state;
}

void
audit_page_state_destroy(AuditPageState *state)
{
    free(state);
}

bool
audit_page_state_relation_create(AuditPageState *state,
                                 const AuditRelationGeneration *relation,
                                 XLogRecPtr lsn, char *error, size_t size)
{
    if (!state || !valid_relation(relation))
        return state_error(error, size, "page-state: invalid relation generation");
    return state->backend.relation_create(state->backend.context, relation,
                                          lsn, error, size);
}

bool
audit_page_state_relation_close(AuditPageState *state,
                                const AuditRelationGeneration *relation,
                                XLogRecPtr lsn, char *error, size_t size)
{
    if (!state || !valid_relation(relation))
        return state_error(error, size, "page-state: invalid relation generation");
    return state->backend.relation_close(state->backend.context, relation,
                                         lsn, error, size);
}

bool
audit_page_state_apply_fpi(AuditPageState *state,
                           const AuditRelationGeneration *relation,
                           uint32 block, const AuditPageTuple *tuples,
                           size_t count, AuditPageTrust trust,
                           AuditPageStateSource source, XLogRecPtr lsn,
                           char *error, size_t size)
{
    uint32 previous = 0;
    if (!state || !valid_relation(relation) ||
        (count && !tuples) || trust == AUDIT_PAGE_UNTRUSTED ||
        (source != AUDIT_STATE_SOURCE_FULL_PAGE_IMAGE &&
         source != AUDIT_STATE_SOURCE_INIT_PAGE))
        return state_error(error, size, "page-state: invalid validated page image");
    for (size_t i = 0; i < count; i++)
    {
        if (tuples[i].offset <= previous ||
            tuples[i].offset > state->config.max_offset_number ||
            (tuples[i].slot_state == AUDIT_SLOT_NORMAL &&
             !valid_tuple(state, tuples[i].data, tuples[i].length)) ||
            (tuples[i].slot_state != AUDIT_SLOT_NORMAL &&
             (tuples[i].data || tuples[i].length)))
            return state_error(error, size, "page-state: invalid page image slot");
        previous = tuples[i].offset;
    }
    return state->backend.replace_page(state->backend.context, relation, block,
                                       tuples, count, trust, source, lsn,
                                       error, size);
}

bool
audit_page_state_heap_insert(AuditPageState *state,
                             const AuditRelationGeneration *relation,
                             AuditPhysicalTid tid, const uint8 *tuple,
                             size_t length, AuditPageTrust trust,
                             AuditPageStateSource source, XLogRecPtr lsn,
                             char *error, size_t size)
{
    AuditTupleState value;
    if (!state || !valid_relation(relation) || !valid_tid(state, tid) ||
        !valid_tuple(state, tuple, length))
        return state_error(error, size, "page-state: invalid heap insert");
    value = (AuditTupleState){(uint8 *)tuple, length, true, AUDIT_SLOT_NORMAL,
                              trust, source, lsn};
    return state->backend.store_tuple(state->backend.context, relation, tid,
                                      &value, error, size);
}

bool
audit_page_state_heap_delete(AuditPageState *state,
                             const AuditRelationGeneration *relation,
                             AuditPhysicalTid tid, XLogRecPtr lsn,
                             char *error, size_t size)
{
    if (!state || !valid_relation(relation) || !valid_tid(state, tid))
        return state_error(error, size, "page-state: invalid heap delete");
    return state->backend.set_slot_state(state->backend.context, relation, tid,
                                         AUDIT_SLOT_NOT_NORMAL, lsn,
                                         error, size);
}

bool
audit_page_state_heap_update(AuditPageState *state,
                             const AuditRelationGeneration *old_relation,
                             AuditPhysicalTid old_tid,
                             const AuditRelationGeneration *new_relation,
                             AuditPhysicalTid new_tid, const uint8 *new_tuple,
                             size_t length, AuditPageTrust trust, XLogRecPtr lsn,
                             char *error, size_t size)
{
    if (!state || !valid_relation(old_relation) || !valid_relation(new_relation) ||
        !valid_tid(state, old_tid) || !valid_tid(state, new_tid) ||
        !valid_tuple(state, new_tuple, length))
        return state_error(error, size, "page-state: invalid heap update");
    AuditTupleState value = {
        (uint8 *)new_tuple, length, true, AUDIT_SLOT_NORMAL, trust,
        AUDIT_STATE_SOURCE_WAL_TUPLE, lsn
    };
    return state->backend.apply_heap_update(
        state->backend.context, old_relation, old_tid, new_relation, new_tid,
        &value, lsn, error, size);
}

bool
audit_page_state_truncate(AuditPageState *state,
                          const AuditRelationGeneration *relation,
                          uint32 first_removed_block, XLogRecPtr lsn,
                          char *error, size_t size)
{
    if (!state || !valid_relation(relation))
        return state_error(error, size, "page-state: invalid truncate");
    return state->backend.truncate_relation(state->backend.context, relation,
                                            first_removed_block, lsn,
                                            error, size);
}

bool
audit_page_state_mark_page_untrusted(AuditPageState *state,
                                     const AuditRelationGeneration *relation,
                                     uint32 block, XLogRecPtr lsn,
                                     char *error, size_t size)
{
    if (!state || !valid_relation(relation))
        return state_error(error, size, "page-state: invalid page invalidation");
    return state->backend.invalidate_page(state->backend.context, relation,
                                          block, lsn, error, size);
}

bool
audit_page_state_mark_gap(AuditPageState *state, XLogRecPtr lsn,
                          char *error, size_t size)
{
    if (!state)
        return state_error(error, size, "page-state: invalid gap");
    return state->backend.invalidate_all(state->backend.context, lsn,
                                         error, size);
}

bool
audit_page_state_load_tuple(AuditPageState *state,
                            const AuditRelationGeneration *relation,
                            AuditPhysicalTid tid, XLogRecPtr before_lsn,
                            AuditTupleState *tuple,
                            char *error, size_t size)
{
    if (tuple)
        memset(tuple, 0, sizeof(*tuple));
    if (!state || !valid_relation(relation) || !valid_tid(state, tid) || !tuple)
        return state_error(error, size, "page-state: invalid tuple lookup");
    if (!state->backend.load_tuple(state->backend.context, relation, tid,
                                   before_lsn, tuple,
                                   error, size))
        return false;
    if (tuple->present && tuple->slot_state == AUDIT_SLOT_NORMAL &&
        !valid_tuple(state, tuple->data, tuple->length))
    {
        state->backend.release_tuple(state->backend.context, tuple);
        memset(tuple, 0, sizeof(*tuple));
        return state_error(error, size, "page-state: backend returned invalid tuple");
    }
    return true;
}

void
audit_page_state_release_tuple(AuditPageState *state, AuditTupleState *tuple)
{
    if (state && tuple)
        state->backend.release_tuple(state->backend.context, tuple);
    if (tuple)
        memset(tuple, 0, sizeof(*tuple));
}
