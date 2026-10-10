#include "postgres.h"
#include "update_reconstruction.h"
#include "access/heapam_xlog.h"
#include "access/htup_details.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static bool
reconstruction_error(char *error, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(error, size, format, args);
    va_end(args);
    return false;
}

static bool
same_page(const AuditUpdateReconstructionInput *input)
{
    return input->old_relation.tablespace == input->new_relation.tablespace &&
           input->old_relation.database_oid ==
               input->new_relation.database_oid &&
           input->old_relation.relfilenode ==
               input->new_relation.relfilenode &&
           input->old_relation.fork_number ==
               input->new_relation.fork_number &&
           input->old_relation.generation ==
               input->new_relation.generation &&
           input->old_tid.block == input->new_tid.block;
}

static bool
read_u16(const uint8 **cursor, const uint8 *end, uint16 *value)
{
    if ((size_t)(end - *cursor) < sizeof(*value))
        return false;
    memcpy(value, *cursor, sizeof(*value));
    *cursor += sizeof(*value);
    return true;
}

static void
set_result(AuditUpdateReconstruction *result, AuditReconstructionStatus status,
           const char *warning)
{
    result->status = status;
    result->certainty = status == AUDIT_RECONSTRUCTION_EXACT ?
                        "certain" : "incomplete";
    result->warning = warning;
}

bool
audit_reconstruct_heap_update(AuditPageState *state,
                              const AuditUpdateReconstructionInput *input,
                              AuditUpdateReconstruction *result,
                              char *error, size_t size)
{
    const uint8 *cursor, *end, *fragment;
    uint16 prefix = 0, suffix = 0;
    xl_heap_header logged_header;
    AuditTupleState old = {0};
    HeapTupleHeader old_header = NULL, after;
    size_t fragment_length, header_tail, old_data_length = 0, after_length;
    uint8 *write;
    bool needs_old;

    if (!result)
        return reconstruction_error(error, size,
                                    "update-reconstruction: result is required");
    memset(result, 0, sizeof(*result));
    set_result(result, AUDIT_RECONSTRUCTION_INVALID, "update_delta_malformed");
    if (!state || !input || !input->block_data)
        return reconstruction_error(error, size,
                                    "update-reconstruction: invalid request");
    result->provenance.method = "postgres_heap_redo";
    result->provenance.base_relation = input->old_relation;
    result->provenance.base_tid = input->old_tid;
    result->provenance.used_prefix = input->prefix_from_old;
    result->provenance.used_suffix = input->suffix_from_old;
    if ((input->prefix_from_old || input->suffix_from_old) && !same_page(input))
        return true;
    if (input->hot_update && !same_page(input))
        return true;

    cursor = input->block_data;
    end = cursor + input->block_data_length;
    if (input->prefix_from_old && !read_u16(&cursor, end, &prefix))
        return true;
    if (input->suffix_from_old && !read_u16(&cursor, end, &suffix))
        return true;
    result->provenance.prefix_length = prefix;
    result->provenance.suffix_length = suffix;
    if ((size_t)(end - cursor) < SizeOfHeapHeader)
        return true;
    memcpy(&logged_header, cursor, SizeOfHeapHeader);
    cursor += SizeOfHeapHeader;
    fragment = cursor;
    fragment_length = (size_t)(end - cursor);
    if (logged_header.t_hoff < SizeofHeapTupleHeader)
        return true;
    header_tail = logged_header.t_hoff - SizeofHeapTupleHeader;
    if (fragment_length < header_tail)
        return true;

    needs_old = input->prefix_from_old || input->suffix_from_old;
    if (needs_old)
    {
        if (!audit_page_state_load_tuple(state, &input->old_relation,
                                         input->old_tid, input->record_lsn,
                                         &old, error, size))
            return false;
        result->provenance.base_applied_lsn = old.applied_lsn;
        result->provenance.base_trust = old.trust;
        if (!old.present)
        {
            set_result(result, AUDIT_RECONSTRUCTION_UNAVAILABLE,
                       "update_base_tid_missing");
            audit_page_state_release_tuple(state, &old);
            return true;
        }
        if (old.slot_state != AUDIT_SLOT_NORMAL)
        {
            set_result(result, AUDIT_RECONSTRUCTION_UNAVAILABLE,
                       "update_base_line_pointer_not_normal");
            audit_page_state_release_tuple(state, &old);
            return true;
        }
        if (old.trust == AUDIT_PAGE_UNTRUSTED)
        {
            set_result(result, AUDIT_RECONSTRUCTION_UNAVAILABLE,
                       "update_base_page_untrusted");
            audit_page_state_release_tuple(state, &old);
            return true;
        }
        old_header = (HeapTupleHeader)old.data;
        old_data_length = old.length - old_header->t_hoff;
        if ((size_t)prefix + suffix > old_data_length)
        {
            audit_page_state_release_tuple(state, &old);
            return true;
        }
    }

    if (fragment_length > SIZE_MAX - SizeofHeapTupleHeader - prefix - suffix)
        goto malformed;
    after_length = SizeofHeapTupleHeader + fragment_length + prefix + suffix;
    if (logged_header.t_hoff > after_length ||
        after_length > MaxHeapTupleSize)
        goto malformed;
    result->after_tuple = calloc(1, after_length);
    if (!result->after_tuple)
        goto oom;
    result->after_tuple_length = after_length;
    after = (HeapTupleHeader)result->after_tuple;
    write = result->after_tuple + SizeofHeapTupleHeader;

    if (prefix > 0)
    {
        memcpy(write, fragment, header_tail);
        write += header_tail;
        fragment += header_tail;
        fragment_length -= header_tail;
        memcpy(write, old.data + old_header->t_hoff, prefix);
        write += prefix;
    }
    memcpy(write, fragment, fragment_length);
    write += fragment_length;
    if (suffix > 0)
    {
        memcpy(write, old.data + old.length - suffix, suffix);
        write += suffix;
    }
    if ((size_t)(write - result->after_tuple) != after_length)
        goto malformed;

    after->t_infomask2 = logged_header.t_infomask2;
    after->t_infomask = logged_header.t_infomask;
    after->t_hoff = logged_header.t_hoff;
    HeapTupleHeaderSetXmin(after, input->xid);
    HeapTupleHeaderSetCmin(after, FirstCommandId);
    HeapTupleHeaderSetXmax(after, input->new_xmax);
    ItemPointerSet(&after->t_ctid, input->new_tid.block, input->new_tid.offset);

    result->after_decoder_tuple_length =
        SizeOfHeapHeader + after_length - SizeofHeapTupleHeader;
    result->after_decoder_tuple = malloc(result->after_decoder_tuple_length);
    if (!result->after_decoder_tuple)
        goto oom;
    memcpy(result->after_decoder_tuple, &logged_header, SizeOfHeapHeader);
    memcpy(result->after_decoder_tuple + SizeOfHeapHeader,
           result->after_tuple + SizeofHeapTupleHeader,
           after_length - SizeofHeapTupleHeader);
    if (!audit_page_state_heap_update(state, &input->old_relation,
                                      input->old_tid, &input->new_relation,
                                      input->new_tid, result->after_tuple,
                                      result->after_tuple_length,
                                      needs_old ? old.trust :
                                      input->new_tuple_trust,
                                      input->record_lsn, error, size))
        goto backend_failure;
    set_result(result, AUDIT_RECONSTRUCTION_EXACT, NULL);
    audit_page_state_release_tuple(state, &old);
    return true;

malformed:
    audit_update_reconstruction_free(result);
    set_result(result, AUDIT_RECONSTRUCTION_INVALID, "update_delta_malformed");
    audit_page_state_release_tuple(state, &old);
    return true;
oom:
    audit_update_reconstruction_free(result);
    audit_page_state_release_tuple(state, &old);
    return reconstruction_error(error, size,
                                "update-reconstruction: out of memory");
backend_failure:
    audit_update_reconstruction_free(result);
    audit_page_state_release_tuple(state, &old);
    return false;
}

void
audit_update_reconstruction_free(AuditUpdateReconstruction *result)
{
    if (!result)
        return;
    free(result->after_tuple);
    free(result->after_decoder_tuple);
    memset(result, 0, sizeof(*result));
}

const char *
audit_reconstruction_status_name(AuditReconstructionStatus status)
{
    switch (status)
    {
        case AUDIT_RECONSTRUCTION_EXACT: return "exact";
        case AUDIT_RECONSTRUCTION_UNAVAILABLE: return "unavailable";
        default: return "invalid";
    }
}
