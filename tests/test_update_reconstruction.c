#include "postgres.h"
#include "page_state.h"
#include "update_reconstruction.h"
#include "access/heapam_xlog.h"
#include "access/htup_details.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_TUPLE_LIMIT 512

typedef struct DiskRecord
{
    AuditRelationGeneration relation;
    AuditPhysicalTid tid;
    uint32 magic;
    uint32 length;
    uint8 present;
    uint8 slot_state;
    uint8 trust;
    uint8 source;
    XLogRecPtr lsn;
    uint8 data[TEST_TUPLE_LIMIT];
} DiskRecord;

typedef struct DiskBackend
{
    char path[128];
    unsigned relation_creates;
    unsigned relation_closes;
    unsigned replacements;
    unsigned truncates;
    unsigned invalidated_pages;
    unsigned gaps;
    XLogRecPtr gap_lsn;
} DiskBackend;

static bool
same_relation(const AuditRelationGeneration *a,
              const AuditRelationGeneration *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

static bool
append_record(DiskBackend *backend, const DiskRecord *record,
              char *error, size_t error_size)
{
    int fd = open(backend->path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0 || write(fd, record, sizeof(*record)) != sizeof(*record) ||
        fsync(fd) != 0 || close(fd) != 0)
    {
        if (fd >= 0)
            close(fd);
        snprintf(error, error_size, "test disk backend write failed");
        return false;
    }
    return true;
}

static bool
relation_create(void *context, const AuditRelationGeneration *relation,
                XLogRecPtr lsn, char *error, size_t error_size)
{
    ((DiskBackend *)context)->relation_creates++;
    return true;
}

static bool
relation_close(void *context, const AuditRelationGeneration *relation,
               XLogRecPtr lsn, char *error, size_t error_size)
{
    ((DiskBackend *)context)->relation_closes++;
    return true;
}

static bool
load_tuple(void *context, const AuditRelationGeneration *relation,
           AuditPhysicalTid tid, XLogRecPtr before_lsn, AuditTupleState *tuple,
           char *error, size_t error_size)
{
    DiskBackend *backend = context;
    DiskRecord record, match = {0};
    FILE *file = fopen(backend->path, "rb");
    if (!file)
        return true;
    while (fread(&record, sizeof(record), 1, file) == 1)
        if (record.magic == 0x41554454 &&
            same_relation(&record.relation, relation) &&
            record.tid.block == tid.block && record.tid.offset == tid.offset &&
            record.lsn < before_lsn)
            match = record;
    fclose(file);
    if (!match.magic)
        return true;
    tuple->present = match.present;
    tuple->slot_state = (AuditSlotState)match.slot_state;
    tuple->trust = (AuditPageTrust)match.trust;
    tuple->source = (AuditPageStateSource)match.source;
    tuple->applied_lsn = match.lsn;
    if (backend->gap_lsn > match.lsn && backend->gap_lsn < before_lsn)
        tuple->trust = AUDIT_PAGE_UNTRUSTED;
    tuple->length = match.length;
    if (match.length)
    {
        tuple->data = malloc(match.length);
        assert(tuple->data);
        memcpy(tuple->data, match.data, match.length);
    }
    return true;
}

static bool
store_tuple(void *context, const AuditRelationGeneration *relation,
            AuditPhysicalTid tid, const AuditTupleState *tuple,
            char *error, size_t error_size)
{
    DiskRecord record = {0};
    assert(tuple->length <= sizeof(record.data));
    record.relation = *relation;
    record.tid = tid;
    record.magic = 0x41554454;
    record.length = tuple->length;
    record.present = tuple->present;
    record.slot_state = tuple->slot_state;
    record.trust = tuple->trust;
    record.source = tuple->source;
    record.lsn = tuple->applied_lsn;
    memcpy(record.data, tuple->data, tuple->length);
    return append_record(context, &record, error, error_size);
}

static bool
set_slot_state(void *context, const AuditRelationGeneration *relation,
               AuditPhysicalTid tid, AuditSlotState state, XLogRecPtr lsn,
               char *error, size_t error_size)
{
    AuditTupleState tuple = {0};
    if (!load_tuple(context, relation, tid, lsn, &tuple, error, error_size))
        return false;
    tuple.present = true;
    tuple.slot_state = state;
    tuple.applied_lsn = lsn;
    bool result = store_tuple(context, relation, tid, &tuple, error, error_size);
    free(tuple.data);
    return result;
}

static bool
apply_heap_update(void *context,
                  const AuditRelationGeneration *old_relation,
                  AuditPhysicalTid old_tid,
                  const AuditRelationGeneration *new_relation,
                  AuditPhysicalTid new_tid, const AuditTupleState *new_tuple,
                  XLogRecPtr lsn, char *error, size_t error_size)
{
    if (!set_slot_state(context, old_relation, old_tid,
                        AUDIT_SLOT_NOT_NORMAL, lsn, error, error_size))
        return false;
    return store_tuple(context, new_relation, new_tid, new_tuple,
                       error, error_size);
}

static bool
replace_page(void *context, const AuditRelationGeneration *relation,
             uint32 block, const AuditPageTuple *tuples, size_t tuple_count,
             AuditPageTrust trust, AuditPageStateSource source, XLogRecPtr lsn,
             char *error, size_t error_size)
{
    DiskBackend *backend = context;
    backend->replacements++;
    for (size_t i = 0; i < tuple_count; i++)
    {
        AuditTupleState tuple = {
            .data = (uint8 *)tuples[i].data,
            .length = tuples[i].length,
            .present = true,
            .slot_state = tuples[i].slot_state,
            .trust = trust,
            .source = source,
            .applied_lsn = lsn
        };
        AuditPhysicalTid tid = {block, tuples[i].offset};
        if (!store_tuple(context, relation, tid, &tuple, error, error_size))
            return false;
    }
    return true;
}

static bool
truncate_relation(void *context, const AuditRelationGeneration *relation,
                  uint32 first_removed_block, XLogRecPtr lsn,
                  char *error, size_t error_size)
{
    ((DiskBackend *)context)->truncates++;
    return true;
}

static bool
invalidate_page(void *context, const AuditRelationGeneration *relation,
                uint32 block, XLogRecPtr lsn, char *error, size_t error_size)
{
    ((DiskBackend *)context)->invalidated_pages++;
    return true;
}

static bool
invalidate_all(void *context, XLogRecPtr lsn,
               char *error, size_t error_size)
{
    ((DiskBackend *)context)->gaps++;
    ((DiskBackend *)context)->gap_lsn = lsn;
    return true;
}

static void
release_tuple(void *context, AuditTupleState *tuple)
{
    free(tuple->data);
}

static size_t
make_tuple(uint8 *tuple, const char *data, AuditPhysicalTid tid)
{
    HeapTupleHeader header = (HeapTupleHeader)tuple;
    size_t data_length = strlen(data);
    memset(tuple, 0, TEST_TUPLE_LIMIT);
    header->t_infomask2 = 3;
    header->t_hoff = SizeofHeapTupleHeader + 1;
    ItemPointerSet(&header->t_ctid, tid.block, tid.offset);
    tuple[SizeofHeapTupleHeader] = 7;
    memcpy(tuple + header->t_hoff, data, data_length);
    return header->t_hoff + data_length;
}

static size_t
make_delta(uint8 *delta, bool prefix_flag, uint16 prefix,
           bool suffix_flag, uint16 suffix, const char *middle)
{
    xl_heap_header header = {
        .t_infomask2 = 3,
        .t_infomask = 0,
        .t_hoff = SizeofHeapTupleHeader + 1
    };
    uint8 *cursor = delta;
    if (prefix_flag)
    {
        memcpy(cursor, &prefix, sizeof(prefix));
        cursor += sizeof(prefix);
    }
    if (suffix_flag)
    {
        memcpy(cursor, &suffix, sizeof(suffix));
        cursor += sizeof(suffix);
    }
    memcpy(cursor, &header, SizeOfHeapHeader);
    cursor += SizeOfHeapHeader;
    *cursor++ = 7;
    memcpy(cursor, middle, strlen(middle));
    cursor += strlen(middle);
    return cursor - delta;
}

static AuditUpdateReconstruction
reconstruct(AuditPageState *state, AuditRelationGeneration relation,
            AuditPhysicalTid old_tid, AuditPhysicalTid new_tid,
            bool prefix_flag, uint16 prefix, bool suffix_flag, uint16 suffix,
            const char *middle)
{
    uint8 delta[128];
    char error[256];
    AuditUpdateReconstruction result;
    AuditUpdateReconstructionInput input = {
        .old_relation = relation,
        .new_relation = relation,
        .old_tid = old_tid,
        .new_tid = new_tid,
        .xid = 44,
        .new_xmax = 0,
        .record_lsn = 200,
        .new_tuple_trust = AUDIT_PAGE_IMAGE_PROVED,
        .prefix_from_old = prefix_flag,
        .suffix_from_old = suffix_flag
    };
    input.block_data_length = make_delta(delta, prefix_flag, prefix,
                                         suffix_flag, suffix, middle);
    input.block_data = delta;
    assert(audit_reconstruct_heap_update(state, &input, &result,
                                         error, sizeof(error)));
    return result;
}

static void
assert_body(const AuditUpdateReconstruction *result, const char *expected)
{
    HeapTupleHeader header = (HeapTupleHeader)result->after_tuple;
    assert(result->status == AUDIT_RECONSTRUCTION_EXACT);
    assert(strcmp(result->certainty, "certain") == 0);
    assert(result->warning == NULL);
    assert(result->after_decoder_tuple != NULL);
    assert(result->after_decoder_tuple_length ==
           SizeOfHeapHeader + result->after_tuple_length -
           SizeofHeapTupleHeader);
    assert(result->after_tuple_length - header->t_hoff == strlen(expected));
    assert(memcmp(result->after_tuple + header->t_hoff,
                  expected, strlen(expected)) == 0);
}

int
main(void)
{
    assert(audit_page_image_item_valid(128, 8192, 256, 64,
                                       SizeofHeapTupleHeader));
    assert(!audit_page_image_item_valid(128, 8192, 127, 64,
                                        SizeofHeapTupleHeader));
    assert(!audit_page_image_item_valid(128, 8192, 8191, 2,
                                        SizeofHeapTupleHeader));
    assert(!audit_page_image_item_valid(128, 8192, 256,
                                        SizeofHeapTupleHeader - 1,
                                        SizeofHeapTupleHeader));
    assert(!audit_page_image_item_valid(128, 8192, 8192,
                                        SizeofHeapTupleHeader,
                                        SizeofHeapTupleHeader));
    char error[256];
    DiskBackend disk = {0};
    AuditPageStateConfig config = {TEST_TUPLE_LIMIT, 128};
    AuditPageStateBackend backend = {
        .context = &disk,
        .relation_create = relation_create,
        .relation_close = relation_close,
        .load_tuple = load_tuple,
        .store_tuple = store_tuple,
        .set_slot_state = set_slot_state,
        .apply_heap_update = apply_heap_update,
        .replace_page = replace_page,
        .truncate_relation = truncate_relation,
        .invalidate_page = invalidate_page,
        .invalidate_all = invalidate_all,
        .release_tuple = release_tuple
    };
    AuditRelationGeneration relation = {1663, 5, 20000, 0, 1};
    AuditPhysicalTid old_tid = {7, 2};
    uint8 old_tuple[TEST_TUPLE_LIMIT];
    size_t old_length;
    AuditUpdateReconstruction result;
    AuditTupleState loaded;

    snprintf(disk.path, sizeof(disk.path),
             "tests/page-state-pg%d-%ld.bin",
             PG_VERSION_NUM / 10000, (long)getpid());
    unlink(disk.path);
    AuditPageState *state = audit_page_state_create(&config, &backend,
                                                    error, sizeof(error));
    assert(state);
    assert(audit_page_state_relation_create(state, &relation, 10,
                                            error, sizeof(error)));
    old_length = make_tuple(old_tuple, "abcdefghij", old_tid);
    assert(audit_page_state_heap_insert(state, &relation, old_tid, old_tuple,
                                        old_length, AUDIT_PAGE_ORIGIN_PROVED,
                                        AUDIT_STATE_SOURCE_WAL_TUPLE, 100,
                                        error, sizeof(error)));

    result = reconstruct(state, relation, old_tid,
                         (AuditPhysicalTid){7, 3}, true, 3, true, 2, "XYZ");
    assert_body(&result, "abcXYZij");
    assert(strcmp(result.provenance.method, "postgres_heap_redo") == 0);
    assert(result.provenance.base_applied_lsn == 100);
    assert(result.provenance.base_trust == AUDIT_PAGE_ORIGIN_PROVED);
    audit_update_reconstruction_free(&result);

    old_tid = (AuditPhysicalTid){8, 2};
    old_length = make_tuple(old_tuple, "abcdefghij", old_tid);
    assert(audit_page_state_heap_insert(state, &relation, old_tid, old_tuple,
                                        old_length, AUDIT_PAGE_IMAGE_PROVED,
                                        AUDIT_STATE_SOURCE_FULL_PAGE_IMAGE, 110,
                                        error, sizeof(error)));
    result = reconstruct(state, relation, old_tid,
                         (AuditPhysicalTid){8, 3}, true, 3, false, 0, "XYZ");
    assert_body(&result, "abcXYZ");
    audit_update_reconstruction_free(&result);

    old_tid = (AuditPhysicalTid){9, 2};
    old_length = make_tuple(old_tuple, "abcdefghij", old_tid);
    assert(audit_page_state_heap_insert(state, &relation, old_tid, old_tuple,
                                        old_length, AUDIT_PAGE_IMAGE_PROVED,
                                        AUDIT_STATE_SOURCE_FULL_PAGE_IMAGE, 120,
                                        error, sizeof(error)));
    result = reconstruct(state, relation, old_tid,
                         (AuditPhysicalTid){9, 3}, false, 0, true, 2, "XYZ");
    assert_body(&result, "XYZij");
    audit_update_reconstruction_free(&result);

    old_tid = (AuditPhysicalTid){10, 2};
    old_length = make_tuple(old_tuple, "abcdefghij", old_tid);
    assert(audit_page_state_heap_insert(state, &relation, old_tid, old_tuple,
                                        old_length, AUDIT_PAGE_IMAGE_PROVED,
                                        AUDIT_STATE_SOURCE_FULL_PAGE_IMAGE, 130,
                                        error, sizeof(error)));
    result = reconstruct(state, relation, old_tid,
                         (AuditPhysicalTid){10, 3}, true, 0, true, 0, "XYZ");
    assert_body(&result, "XYZ");
    audit_update_reconstruction_free(&result);

    result = reconstruct(state, relation, (AuditPhysicalTid){99, 1},
                         (AuditPhysicalTid){99, 2}, true, 1, false, 0, "X");
    assert(result.status == AUDIT_RECONSTRUCTION_UNAVAILABLE);
    assert(strcmp(result.warning, "update_base_tid_missing") == 0);
    assert(strcmp(result.certainty, "incomplete") == 0);
    assert(result.after_tuple == NULL);

    old_tid = (AuditPhysicalTid){11, 2};
    old_length = make_tuple(old_tuple, "abc", old_tid);
    assert(audit_page_state_heap_insert(state, &relation, old_tid, old_tuple,
                                        old_length, AUDIT_PAGE_UNTRUSTED,
                                        AUDIT_STATE_SOURCE_WAL_TUPLE, 140,
                                        error, sizeof(error)));
    result = reconstruct(state, relation, old_tid,
                         (AuditPhysicalTid){11, 3}, true, 1, false, 0, "X");
    assert(result.status == AUDIT_RECONSTRUCTION_UNAVAILABLE);
    assert(strcmp(result.warning, "update_base_page_untrusted") == 0);

    old_tid = (AuditPhysicalTid){12, 2};
    old_length = make_tuple(old_tuple, "abc", old_tid);
    assert(audit_page_state_heap_insert(state, &relation, old_tid, old_tuple,
                                        old_length, AUDIT_PAGE_IMAGE_PROVED,
                                        AUDIT_STATE_SOURCE_FULL_PAGE_IMAGE, 150,
                                        error, sizeof(error)));
    assert(audit_page_state_heap_delete(state, &relation, old_tid, 151,
                                        error, sizeof(error)));
    result = reconstruct(state, relation, old_tid,
                         (AuditPhysicalTid){12, 3}, true, 1, false, 0, "X");
    assert(result.status == AUDIT_RECONSTRUCTION_UNAVAILABLE);
    assert(strcmp(result.warning,
                  "update_base_line_pointer_not_normal") == 0);

    old_tid = (AuditPhysicalTid){13, 2};
    old_length = make_tuple(old_tuple, "abc", old_tid);
    assert(audit_page_state_heap_insert(state, &relation, old_tid, old_tuple,
                                        old_length, AUDIT_PAGE_IMAGE_PROVED,
                                        AUDIT_STATE_SOURCE_FULL_PAGE_IMAGE, 160,
                                        error, sizeof(error)));
    result = reconstruct(state, relation, old_tid,
                         (AuditPhysicalTid){13, 3}, true, 3, true, 1, "X");
    assert(result.status == AUDIT_RECONSTRUCTION_INVALID);
    assert(strcmp(result.warning, "update_delta_malformed") == 0);

    result = reconstruct(state, relation, old_tid,
                         (AuditPhysicalTid){13, 4}, false, 0, false, 0, "whole");
    assert_body(&result, "whole");
    audit_update_reconstruction_free(&result);

    uint8 malformed[SizeOfHeapHeader + 1] = {0};
    AuditUpdateReconstructionInput malformed_input = {
        .old_relation = relation,
        .new_relation = relation,
        .old_tid = old_tid,
        .new_tid = {13, 3},
        .xid = 1,
        .record_lsn = 170,
        .block_data = malformed,
        .block_data_length = sizeof(malformed)
    };
    xl_heap_header *bad_header = (xl_heap_header *)malformed;
    bad_header->t_hoff = SizeofHeapTupleHeader + 10;
    assert(audit_reconstruct_heap_update(state, &malformed_input, &result,
                                         error, sizeof(error)));
    assert(result.status == AUDIT_RECONSTRUCTION_INVALID);

    malformed_input.prefix_from_old = true;
    malformed_input.new_relation.generation = 2;
    assert(audit_reconstruct_heap_update(state, &malformed_input, &result,
                                         error, sizeof(error)));
    assert(result.status == AUDIT_RECONSTRUCTION_INVALID);

    malformed_input.new_relation = relation;
    malformed_input.new_tid.block = 14;
    malformed_input.hot_update = true;
    malformed_input.prefix_from_old = false;
    assert(audit_reconstruct_heap_update(state, &malformed_input, &result,
                                         error, sizeof(error)));
    assert(result.status == AUDIT_RECONSTRUCTION_INVALID);

    AuditPageTuple page_tuples[2] = {
        {2, old_tuple, old_length, AUDIT_SLOT_NORMAL},
        {1, old_tuple, old_length, AUDIT_SLOT_NORMAL}
    };
    assert(!audit_page_state_apply_fpi(state, &relation, 20, page_tuples, 2,
                                       AUDIT_PAGE_IMAGE_PROVED,
                                       AUDIT_STATE_SOURCE_FULL_PAGE_IMAGE, 180,
                                       error, sizeof(error)));
    assert(audit_page_state_apply_fpi(state, &relation, 20, page_tuples, 1,
                                      AUDIT_PAGE_IMAGE_PROVED,
                                      AUDIT_STATE_SOURCE_FULL_PAGE_IMAGE, 181,
                                      error, sizeof(error)));
    assert(audit_page_state_truncate(state, &relation, 20, 182,
                                     error, sizeof(error)));
    assert(audit_page_state_mark_page_untrusted(state, &relation, 19, 183,
                                                error, sizeof(error)));
    assert(audit_page_state_mark_gap(state, 184, error, sizeof(error)));
    old_tid = (AuditPhysicalTid){21, 2};
    old_length = make_tuple(old_tuple, "abcdef", old_tid);
    assert(audit_page_state_heap_insert(state, &relation, old_tid, old_tuple,
                                        old_length, AUDIT_PAGE_IMAGE_PROVED,
                                        AUDIT_STATE_SOURCE_WAL_TUPLE, 170,
                                        error, sizeof(error)));
    result = reconstruct(state, relation, old_tid,
                         (AuditPhysicalTid){21, 3}, true, 2, false, 0, "X");
    assert(result.status == AUDIT_RECONSTRUCTION_UNAVAILABLE);
    assert(strcmp(result.warning, "update_base_page_untrusted") == 0);
    assert(audit_page_state_relation_close(state, &relation, 185,
                                           error, sizeof(error)));
    assert(disk.relation_creates == 1 && disk.relation_closes == 1);
    assert(disk.replacements == 1 && disk.truncates == 1);
    assert(disk.invalidated_pages == 1 && disk.gaps == 1);

    assert(audit_page_state_load_tuple(state, &relation,
                                       (AuditPhysicalTid){8, 3}, UINT64_MAX,
                                       &loaded,
                                       error, sizeof(error)));
    assert(loaded.present && loaded.slot_state == AUDIT_SLOT_NORMAL);
    audit_page_state_release_tuple(state, &loaded);
    audit_page_state_destroy(state);
    assert(unlink(disk.path) == 0);
    puts("persistent page-state and update reconstruction tests passed");
    return 0;
}
