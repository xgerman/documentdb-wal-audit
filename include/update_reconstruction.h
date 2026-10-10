#ifndef DOCUMENTDB_WAL_AUDIT_UPDATE_RECONSTRUCTION_H
#define DOCUMENTDB_WAL_AUDIT_UPDATE_RECONSTRUCTION_H

#include "page_state.h"

typedef enum AuditReconstructionStatus
{
    AUDIT_RECONSTRUCTION_EXACT = 0,
    AUDIT_RECONSTRUCTION_UNAVAILABLE,
    AUDIT_RECONSTRUCTION_INVALID
} AuditReconstructionStatus;

typedef struct AuditUpdateReconstructionInput
{
    AuditRelationGeneration old_relation;
    AuditRelationGeneration new_relation;
    AuditPhysicalTid old_tid;
    AuditPhysicalTid new_tid;
    TransactionId xid;
    TransactionId new_xmax;
    XLogRecPtr record_lsn;
    bool hot_update;
    AuditPageTrust new_tuple_trust;
    bool prefix_from_old;
    bool suffix_from_old;
    const uint8 *block_data;
    size_t block_data_length;
} AuditUpdateReconstructionInput;

typedef struct AuditUpdateProvenance
{
    const char *method;
    AuditRelationGeneration base_relation;
    AuditPhysicalTid base_tid;
    XLogRecPtr base_applied_lsn;
    AuditPageTrust base_trust;
    bool used_prefix;
    bool used_suffix;
    uint16 prefix_length;
    uint16 suffix_length;
} AuditUpdateProvenance;

typedef struct AuditUpdateReconstruction
{
    AuditReconstructionStatus status;
    const char *certainty;
    const char *warning;
    uint8 *after_tuple;
    size_t after_tuple_length;
    /*
     * Compact xl_heap_header + tuple data form accepted by the existing BSON
     * tuple decoder.  A successful caller decode is the recovered `after`
     * document; failed decode must downgrade the event to incomplete with
     * update_after_tuple_invalid.
     */
    uint8 *after_decoder_tuple;
    size_t after_decoder_tuple_length;
    AuditUpdateProvenance provenance;
} AuditUpdateReconstruction;

bool audit_reconstruct_heap_update(AuditPageState *state,
                                   const AuditUpdateReconstructionInput *input,
                                   AuditUpdateReconstruction *result,
                                   char *error, size_t error_size);
void audit_update_reconstruction_free(AuditUpdateReconstruction *result);
const char *audit_reconstruction_status_name(AuditReconstructionStatus status);

#endif
