#ifndef DOCUMENTDB_WAL_AUDIT_H
#define DOCUMENTDB_WAL_AUDIT_H

#include "postgres_fe.h"
#include "access/xlogreader.h"

typedef struct AuditOptions
{
    bool jsonl;
    bool include_aborted;
    bool show_postgres_records;
    bool strict;
    bool redact_documents;
    uint64 max_record_bytes;
    uint64 max_transaction_bytes;
    uint64 max_document_bytes;
    const char *manifest_path;
    const char *spill_dir;
    const char *catalog_cache_path;
    const char *ephemeral_cache_dir;
    bool rebuild_cache;
    bool no_persistent_cache;
    XLogRecPtr from_lsn;
    XLogRecPtr to_lsn;
    TransactionId transaction_filter;
    uint64 system_identifier;
    TimeLineID timeline;
    uint32 wal_segment_size;
} AuditOptions;

typedef struct AuditDecoder AuditDecoder;

AuditDecoder *audit_decoder_create(const AuditOptions *options,
                                  char *error, size_t error_size);
bool audit_decoder_process(AuditDecoder *decoder, XLogReaderState *reader,
                           char *error, size_t error_size);
bool audit_decoder_finish(AuditDecoder *decoder,
                          char *error, size_t error_size);
bool audit_decoder_mark_gap(AuditDecoder *decoder, XLogRecPtr gap_lsn,
                            char *error, size_t error_size);
void audit_decoder_destroy(AuditDecoder *decoder);
bool audit_write_error(const AuditOptions *options, const char *message,
                       XLogRecPtr lsn);

#endif
