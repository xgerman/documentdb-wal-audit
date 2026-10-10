#include "postgres.h"
#include "audit_private.h"
#include "access/heapam_xlog.h"
#include "access/htup_details.h"
#include "access/xact.h"
#include "access/rmgr.h"
#include "page_state.h"
#include "update_reconstruction.h"
#include "storage/sinval.h"
#include "storage/bufpage.h"
#include "storage/itemid.h"
#include "catalog/storage_xlog.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_ACTIVE_TRANSACTIONS 4096
#define MAX_EVENT_BYTES (64U * 1024U * 1024U)

static bool error_message(char *error, size_t size, const char *message);

typedef struct Event
{
    struct Event *next;
    XLogRecPtr lsn;
    bson_t *body;
} Event;

typedef struct Transaction
{
    struct Transaction *next;
    TransactionId xid, parent;
    Event *head, *tail;
    char *spill;
    off_t read_offset;
    uint64 event_count, spill_remaining;
    XLogRecPtr spill_lsn;
    uint32 spill_length;
} Transaction;

static bool physical_event(AuditDecoder *d, XLogReaderState *reader,
                           Transaction *t, const char *warning,
                           char *error, size_t size);

struct AuditDecoder
{
    AuditOptions options;
    AuditManifest manifest;
    AuditCatalogCache *catalog;
    AuditPageState *page_state;
    char *ephemeral_catalog_path;
    Transaction *transactions;
    size_t transaction_count;
    uint64 buffered_bytes;
    bool incomplete;
    bool failed;
};

static AuditRelationGeneration
page_relation(const AuditRelation *relation)
{
    AuditRelationGeneration result = {
        .tablespace = relation->tablespace,
        .database_oid = relation->database_oid,
        .relfilenode = relation->relfilenode,
        .fork_number = MAIN_FORKNUM,
        .generation = 1
    };
    return result;
}

static bool
full_heap_tuple(const uint8 *logged, size_t logged_length,
                TransactionId xid, AuditPhysicalTid tid,
                uint8 **tuple, size_t *tuple_length,
                char *error, size_t size)
{
    xl_heap_header header;
    HeapTupleHeader full;
    if (!logged || logged_length < SizeOfHeapHeader)
        return error_message(error, size, "heap tuple bytes are unavailable");
    memcpy(&header, logged, SizeOfHeapHeader);
    if (header.t_hoff < SizeofHeapTupleHeader ||
        logged_length - SizeOfHeapHeader >
            MaxHeapTupleSize - SizeofHeapTupleHeader)
        return error_message(error, size, "invalid logged heap tuple");
    *tuple_length = SizeofHeapTupleHeader +
                    logged_length - SizeOfHeapHeader;
    *tuple = calloc(1, *tuple_length);
    if (!*tuple)
        return error_message(error, size,
                             "out of memory reconstructing heap tuple");
    full = (HeapTupleHeader)*tuple;
    full->t_infomask2 = header.t_infomask2;
    full->t_infomask = header.t_infomask;
    full->t_hoff = header.t_hoff;
    HeapTupleHeaderSetXmin(full, xid);
    HeapTupleHeaderSetCmin(full, FirstCommandId);
    ItemPointerSet(&full->t_ctid, tid.block, tid.offset);
    memcpy(*tuple + SizeofHeapTupleHeader,
           logged + SizeOfHeapHeader,
           logged_length - SizeOfHeapHeader);
    return true;
}

static bool
apply_block_image(AuditDecoder *d, XLogReaderState *reader, uint8 block_id,
                  const AuditRelation *relation, char *error, size_t size)
{
    char page_bytes[BLCKSZ];
    Page page = (Page)page_bytes;
    RelFileLocator locator;
    ForkNumber fork;
    BlockNumber block;
    OffsetNumber maxoff;
    AuditPageTuple *tuples;
    AuditRelationGeneration generation;
    bool ok;
    if (!d->page_state || !XLogRecHasBlockImage(reader, block_id))
        return true;
    XLogRecGetBlockTag(reader, block_id, &locator, &fork, &block);
    if (fork != MAIN_FORKNUM ||
        !RestoreBlockImage(reader, block_id, page_bytes))
        return error_message(error, size, "cannot restore heap full-page image");
    if (((PageHeader)page)->pd_lower < SizeOfPageHeaderData ||
        (((PageHeader)page)->pd_lower - SizeOfPageHeaderData) % sizeof(ItemIdData) != 0 ||
        ((PageHeader)page)->pd_lower > ((PageHeader)page)->pd_upper ||
        ((PageHeader)page)->pd_upper > ((PageHeader)page)->pd_special ||
        ((PageHeader)page)->pd_special > BLCKSZ)
        return error_message(error, size, "invalid heap full-page image");
    maxoff = PageGetMaxOffsetNumber(page);
    tuples = calloc(maxoff, sizeof(*tuples));
    if (maxoff && !tuples)
        return error_message(error, size,
                             "out of memory extracting full-page image");
    for (OffsetNumber off = FirstOffsetNumber; off <= maxoff; off++)
    {
        ItemId item = PageGetItemId(page, off);
        AuditPageTuple *tuple = &tuples[off - FirstOffsetNumber];
        tuple->offset = off;
        if (ItemIdIsNormal(item))
        {
            uint16 item_offset = ItemIdGetOffset(item);
            uint16 item_length = ItemIdGetLength(item);
            if (!audit_page_image_item_valid(
                    ((PageHeader)page)->pd_upper,
                    ((PageHeader)page)->pd_special,
                    item_offset, item_length, SizeofHeapTupleHeader))
            {
                free(tuples);
                return error_message(error, size,
                                     "invalid heap full-page image item");
            }
            tuple->slot_state = AUDIT_SLOT_NORMAL;
            tuple->data = (const uint8 *)PageGetItem(page, item);
            tuple->length = item_length;
        }
        else
            tuple->slot_state = !ItemIdIsUsed(item) ?
                AUDIT_SLOT_UNUSED : AUDIT_SLOT_NOT_NORMAL;
    }
    generation = page_relation(relation);
    ok = audit_page_state_relation_create(d->page_state, &generation,
            reader->ReadRecPtr ? reader->ReadRecPtr - 1 : 0, error, size) &&
         audit_page_state_apply_fpi(d->page_state, &generation, block,
            tuples, maxoff, AUDIT_PAGE_IMAGE_PROVED,
            AUDIT_STATE_SOURCE_FULL_PAGE_IMAGE,
            reader->ReadRecPtr ? reader->ReadRecPtr - 1 : 0,
            error, size);
    free(tuples);
    return ok;
}

static bool
error_message(char *error, size_t size, const char *message)
{
    snprintf(error, size, "%s", message);
    return false;
}

static void
lsn_string(XLogRecPtr lsn, char *value, size_t size)
{
    snprintf(value, size, "%X/%X", (uint32)(lsn >> 32), (uint32)lsn);
}

static bool
append_lsn(bson_t *doc, const char *key, XLogRecPtr lsn)
{
    char value[32];
    lsn_string(lsn, value, sizeof(value));
    return BSON_APPEND_UTF8(doc, key, value);
}

static bool
output_event(const AuditOptions *options, const bson_t *event)
{
    bson_iter_t it;
    bool first = true;
    if (!options->jsonl)
    {
        bson_iter_t op, type, xid;
        const char *kind = "event";
        if (bson_iter_init_find(&type, event, "eventType") && BSON_ITER_HOLDS_UTF8(&type))
            kind = bson_iter_utf8(&type, NULL);
        if (bson_iter_init_find(&op, event, "operation") && BSON_ITER_HOLDS_UTF8(&op))
            kind = bson_iter_utf8(&op, NULL);
        bson_iter_init_find(&xid, event, "transactionId");
        if (fprintf(stdout, "%s transaction=%" PRId64 " ", kind,
                    bson_iter_as_int64(&xid)) < 0)
            return false;
    }
    if (fputc('{', stdout) == EOF || !bson_iter_init(&it, event))
        return false;
    while (bson_iter_next(&it))
    {
        const char *key = bson_iter_key(&it);
        bson_t wrapper;
        char *json, *value, *end;
        size_t length;
        /* Event keys are fixed; values are always escaped by libbson. */
        if (fprintf(stdout, "%s\"%s\":", first ? "" : ",", key) < 0)
            return false;
        first = false;
        bson_init(&wrapper);
        if (!bson_append_value(&wrapper, "v", 1, bson_iter_value(&it)))
        {
            bson_destroy(&wrapper);
            return false;
        }
        if (!strcmp(key, "objectId") || !strcmp(key, "before") || !strcmp(key, "after"))
            json = bson_as_canonical_extended_json(&wrapper, &length);
        else
            json = bson_as_relaxed_extended_json(&wrapper, &length);
        bson_destroy(&wrapper);
        if (!json)
            return false;
        value = strchr(json, ':');
        end = strrchr(json, '}');
        if (!value || !end || end <= value)
        {
            bson_free(json);
            return false;
        }
        value++;
        while (*value == ' ')
            value++;
        while (end > value && end[-1] == ' ')
            end--;
        if (fwrite(value, 1, end - value, stdout) != (size_t)(end - value))
        {
            bson_free(json);
            return false;
        }
        bson_free(json);
    }
    return fputs("}\n", stdout) >= 0 && !ferror(stdout);
}

static bson_t *
new_event(AuditDecoder *d, TransactionId xid, XLogRecPtr lsn,
          const char *type, const char *operation, const char *certainty,
          const char *warning)
{
    bson_t *event = bson_new();
    bson_t warnings;
    if (!event)
        return NULL;
    BSON_APPEND_INT32(event, "schemaVersion", 1);
    BSON_APPEND_UTF8(event, "certainty", certainty);
    BSON_APPEND_UTF8(event, "eventType", type);
    if (operation)
        BSON_APPEND_UTF8(event, "operation", operation);
    else
        BSON_APPEND_NULL(event, "operation");
    BSON_APPEND_NULL(event, "timestamp");
    BSON_APPEND_INT64(event, "timeline", d->options.timeline);
    BSON_APPEND_INT64(event, "transactionId", xid);
    append_lsn(event, "eventLsn", lsn);
    BSON_APPEND_NULL(event, "commitLsn");
    BSON_APPEND_NULL(event, "relation");
    BSON_APPEND_NULL(event, "database");
    BSON_APPEND_NULL(event, "collection");
    BSON_APPEND_NULL(event, "collectionId");
    BSON_APPEND_NULL(event, "objectId");
    BSON_APPEND_NULL(event, "before");
    BSON_APPEND_NULL(event, "after");
    BSON_APPEND_ARRAY_BEGIN(event, "warnings", &warnings);
    if (warning)
        BSON_APPEND_UTF8(&warnings, "0", warning);
    bson_append_array_end(event, &warnings);
    return event;
}

static bool
selected_lsn(AuditDecoder *d, XLogRecPtr lsn)
{
    return (!d->options.from_lsn || lsn >= d->options.from_lsn) &&
           (!d->options.to_lsn || lsn < d->options.to_lsn);
}

static Transaction *
find_transaction(AuditDecoder *d, TransactionId xid)
{
    for (Transaction *t = d->transactions; t; t = t->next)
        if (t->xid == xid)
            return t;
    return NULL;
}

static Transaction *
get_transaction(AuditDecoder *d, TransactionId xid, char *error, size_t size)
{
    Transaction *t = find_transaction(d, xid);
    if (t)
        return t;
    if (!xid || d->transaction_count >= MAX_ACTIVE_TRANSACTIONS)
    {
        error_message(error, size, "active transaction limit exceeded or invalid XID");
        return NULL;
    }
    t = calloc(1, sizeof(*t));
    if (!t)
    {
        error_message(error, size, "out of memory tracking transactions");
        return NULL;
    }
    t->xid = xid;
    t->next = d->transactions;
    d->transactions = t;
    d->transaction_count++;
    return t;
}

static bool
descends_from(AuditDecoder *d, Transaction *t, TransactionId ancestor)
{
    for (size_t i = 0; i <= d->transaction_count; i++)
    {
        if (t->xid == ancestor)
            return true;
        if (!t->parent || !(t = find_transaction(d, t->parent)))
            return false;
    }
    return false;
}

static bool
assign_parent(AuditDecoder *d, TransactionId child, TransactionId parent,
              char *error, size_t size)
{
    Transaction *p = get_transaction(d, parent, error, size);
    Transaction *c = get_transaction(d, child, error, size);
    if (!p || !c)
        return false;
    if (parent == child || descends_from(d, p, child) ||
        (c->parent && c->parent != parent &&
         !descends_from(d, c, parent)))
        return error_message(error, size, "conflicting or cyclic subtransaction assignment");
    c->parent = parent;
    if (d->catalog &&
        !audit_catalog_assign_parent(d->catalog, child, parent, error, size))
        return false;
    return true;
}

static bool
write_all(FILE *file, const void *data, size_t bytes)
{
    return fwrite(data, 1, bytes, file) == bytes;
}

static bool
spill_write(Transaction *t, XLogRecPtr lsn, const bson_t *body,
            char *error, size_t size)
{
    FILE *file = fopen(t->spill, "ab");
    uint32 length = body->len;
    bool ok;
    if (!file)
        return error_message(error, size, "cannot reopen private transaction spill file");
    ok = write_all(file, &lsn, sizeof(lsn)) &&
         write_all(file, &length, sizeof(length)) &&
         write_all(file, bson_get_data(body), length) && !ferror(file);
    if (fclose(file))
        ok = false;
    if (!ok)
        return error_message(error, size, "transaction spill write failed");
    return true;
}

static bool
spill_transaction(AuditDecoder *d, Transaction *t, char *error, size_t size)
{
    size_t length;
    int fd;
    if (!d->options.spill_dir)
        return error_message(error, size,
             "aggregate transaction buffer exceeds --max-transaction-bytes; supply --spill-dir");
    length = strlen(d->options.spill_dir) + 32;
    t->spill = malloc(length);
    if (!t->spill)
        return error_message(error, size, "out of memory creating spill file");
    snprintf(t->spill, length, "%s/wal-audit-XXXXXX", d->options.spill_dir);
    fd = mkstemp(t->spill);
    if (fd < 0)
    {
        free(t->spill);
        t->spill = NULL;
        return error_message(error, size, "cannot create private transaction spill file");
    }
    bool secured = fchmod(fd, S_IRUSR | S_IWUSR) == 0;
    if (close(fd))
        secured = false;
    if (!secured)
        return error_message(error, size, "cannot secure transaction spill file");
    while (t->head)
    {
        Event *e = t->head;
        if (!spill_write(t, e->lsn, e->body, error, size))
            return false;
        t->head = e->next;
        d->buffered_bytes -= sizeof(*e) + e->body->len;
        bson_destroy(e->body);
        free(e);
    }
    t->tail = NULL;
    return true;
}

static bool
buffer_event(AuditDecoder *d, Transaction *t, XLogRecPtr lsn, bson_t *body,
             char *error, size_t size)
{
    Event *e;
    uint64 bytes = sizeof(*e) + body->len;
    if (body->len > MAX_EVENT_BYTES)
    {
        bson_destroy(body);
        return error_message(error, size, "event exceeds bounded decoder event size");
    }
    while (!t->spill && bytes > d->options.max_transaction_bytes - d->buffered_bytes)
    {
        Transaction *victim = t;
        if (!victim->head && bytes <= d->options.max_transaction_bytes)
            for (Transaction *candidate = d->transactions; candidate; candidate = candidate->next)
                if (candidate->head)
                {
                    victim = candidate;
                    break;
                }
        if (!spill_transaction(d, victim, error, size))
        {
            bson_destroy(body);
            return false;
        }
    }
    if (t->spill)
    {
        bool ok = spill_write(t, lsn, body, error, size);
        bson_destroy(body);
        if (!ok)
            return false;
    }
    else
    {
        e = malloc(sizeof(*e));
        if (!e)
        {
            bson_destroy(body);
            return error_message(error, size, "out of memory buffering event");
        }
        e->body = body;
        e->lsn = lsn;
        e->next = NULL;
        if (t->tail)
            t->tail->next = e;
        else
            t->head = e;
        t->tail = e;
        d->buffered_bytes += bytes;
    }
    t->event_count++;
    return true;
}

static bool
spill_peek(Transaction *t, char *error, size_t size)
{
    FILE *file;
    bool ok;
    if (!t->spill_remaining)
        return true;
    file = fopen(t->spill, "rb");
    if (!file)
        return error_message(error, size, "transaction spill read failed");
    ok = !fseeko(file, t->read_offset, SEEK_SET) &&
         fread(&t->spill_lsn, 1, sizeof(t->spill_lsn), file) == sizeof(t->spill_lsn) &&
         fread(&t->spill_length, 1, sizeof(t->spill_length), file) == sizeof(t->spill_length) &&
         t->spill_length >= 5 && t->spill_length <= MAX_EVENT_BYTES;
    if (fclose(file))
        ok = false;
    return ok || error_message(error, size, "invalid or truncated transaction spill data");
}

static bson_t *
take_event(AuditDecoder *d, Transaction *t, char *error, size_t size)
{
    bson_t *body;
    if (t->spill)
    {
        uint8 *data = malloc(t->spill_length);
        FILE *file;
        bool ok;
        if (!data)
        {
            error_message(error, size, "out of memory reading transaction spill");
            return NULL;
        }
        file = fopen(t->spill, "rb");
        if (!file)
        {
            free(data);
            error_message(error, size, "transaction spill read failed");
            return NULL;
        }
        ok = !fseeko(file, t->read_offset + sizeof(XLogRecPtr) + sizeof(uint32), SEEK_SET) &&
             fread(data, 1, t->spill_length, file) == t->spill_length;
        if (fclose(file))
            ok = false;
        body = ok ? bson_new_from_data(data, t->spill_length) : NULL;
        free(data);
        if (!body)
        {
            error_message(error, size, "invalid or truncated transaction spill BSON");
            return NULL;
        }
        t->read_offset += sizeof(XLogRecPtr) + sizeof(uint32) + t->spill_length;
        t->spill_remaining--;
        if (!spill_peek(t, error, size))
        {
            bson_destroy(body);
            return NULL;
        }
    }
    else
    {
        Event *e = t->head;
        body = e->body;
        t->head = e->next;
        if (!t->head)
            t->tail = NULL;
        d->buffered_bytes -= sizeof(*e) + body->len;
        free(e);
    }
    return body;
}

static bool
free_transaction(AuditDecoder *d, Transaction *t)
{
    bool ok = true;
    while (t->head)
    {
        Event *e = t->head;
        t->head = e->next;
        d->buffered_bytes -= sizeof(*e) + e->body->len;
        bson_destroy(e->body);
        free(e);
    }
    if (t->spill && unlink(t->spill))
        ok = false;
    free(t->spill);
    free(t);
    d->transaction_count--;
    return ok;
}

static bool
event_with_outcome(AuditDecoder *d, bson_t *body, TransactionId xid,
                   XLogRecPtr commit, TimestampTz timestamp, const char *outcome)
{
    bson_t event;
    bson_iter_t it;
    char text[64];
    int64 seconds = timestamp / INT64CONST(1000000) + INT64CONST(946684800);
    int micros = timestamp % INT64CONST(1000000);
    time_t epoch;
    struct tm tm;
    if (micros < 0)
    {
        micros += 1000000;
        seconds--;
    }
    epoch = (time_t)seconds;
    if (seconds != (int64)epoch || !gmtime_r(&epoch, &tm) ||
        tm.tm_year < -1900 || tm.tm_year > 8099)
        return false;
    snprintf(text, sizeof(text), "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, micros);
    bson_init(&event);
    bson_iter_init(&it, body);
    while (bson_iter_next(&it))
    {
        const char *key = bson_iter_key(&it);
        if (!strcmp(key, "timestamp"))
            BSON_APPEND_UTF8(&event, key, text);
        else if (!strcmp(key, "commitLsn"))
        {
            if (!strcmp(outcome, "committed"))
                append_lsn(&event, key, commit);
            else
                BSON_APPEND_NULL(&event, key);
        }
        else if (!strcmp(key, "transactionId"))
            BSON_APPEND_INT64(&event, key, xid);
        else
            bson_append_value(&event, key, -1, bson_iter_value(&it));
    }
    BSON_APPEND_UTF8(&event, "outcome", outcome);
    bool ok = output_event(&d->options, &event);
    bson_destroy(&event);
    return ok;
}

static bool
append_catalog_relation(bson_t *event, const AuditCatalogLocator *relation)
{
    bson_t locator;
    if (!BSON_APPEND_DOCUMENT_BEGIN(event, "relation", &locator) ||
        !BSON_APPEND_INT64(&locator, "tblspaceOid", relation->tablespace) ||
        !BSON_APPEND_INT64(&locator, "databaseOid", relation->database_oid) ||
        !BSON_APPEND_INT64(&locator, "relfilenode", relation->relfilenode))
        return false;
    return bson_append_document_end(event, &locator);
}

static bool
append_namespace(bson_t *event, const char *key,
                 const char *database, const char *collection)
{
    bson_t value;
    if (!database)
        return BSON_APPEND_NULL(event, key);
    if (!BSON_APPEND_DOCUMENT_BEGIN(event, key, &value) ||
        !BSON_APPEND_UTF8(&value, "database", database))
        return false;
    if (collection)
    {
        if (!BSON_APPEND_UTF8(&value, "collection", collection))
            return false;
    }
    else if (!BSON_APPEND_NULL(&value, "collection"))
        return false;
    return bson_append_document_end(event, &value);
}

static bson_t *
catalog_event(AuditDecoder *d, const AuditCatalogDelta *delta)
{
    bson_t *event = bson_new();
    bson_t evidence, warnings;
    const char *database = delta->after_database ?
        delta->after_database : delta->before_database;
    const char *collection = delta->after_collection ?
        delta->after_collection : delta->before_collection;
    if (!event)
        return NULL;
    if (!BSON_APPEND_INT32(event, "schemaVersion", 1) ||
        !BSON_APPEND_UTF8(event, "certainty", delta->certainty) ||
        !BSON_APPEND_UTF8(event, "eventType", "catalog") ||
        !BSON_APPEND_UTF8(event, "operation",
                          audit_catalog_operation_name(delta->operation)) ||
        !BSON_APPEND_NULL(event, "timestamp") ||
        !BSON_APPEND_INT64(event, "timeline", d->options.timeline) ||
        !BSON_APPEND_INT64(event, "transactionId", delta->xid) ||
        !append_lsn(event, "eventLsn", delta->event_lsn) ||
        !BSON_APPEND_NULL(event, "commitLsn") ||
        !append_catalog_relation(event, &delta->relation) ||
        !(database ? BSON_APPEND_UTF8(event, "database", database) :
                      BSON_APPEND_NULL(event, "database")) ||
        !(collection ? BSON_APPEND_UTF8(event, "collection", collection) :
                        BSON_APPEND_NULL(event, "collection")) ||
        !(delta->collection_id ?
            BSON_APPEND_INT64(event, "collectionId", delta->collection_id) :
            BSON_APPEND_NULL(event, "collectionId")) ||
        !BSON_APPEND_NULL(event, "objectId") ||
        !append_namespace(event, "before", delta->before_database,
                          delta->before_collection) ||
        !append_namespace(event, "after", delta->after_database,
                          delta->after_collection) ||
        !BSON_APPEND_UTF8(event, "coverage", delta->coverage) ||
        !BSON_APPEND_UTF8(event, "descriptorFingerprint",
                          delta->descriptor_fingerprint) ||
        !BSON_APPEND_BOOL(event, "isView", delta->is_view) ||
        !BSON_APPEND_ARRAY_BEGIN(event, "evidence", &evidence) ||
        !BSON_APPEND_UTF8(&evidence, "0", delta->evidence) ||
        !bson_append_array_end(event, &evidence) ||
        !BSON_APPEND_ARRAY_BEGIN(event, "warnings", &warnings))
        goto fail;
    if (delta->warning &&
        !BSON_APPEND_UTF8(&warnings, "0", delta->warning))
        goto fail;
    if (!bson_append_array_end(event, &warnings))
        goto fail;
    return event;
fail:
    bson_destroy(event);
    return NULL;
}

static bool
resolve_catalog(AuditDecoder *d, Transaction *root, TransactionId xid,
                XLogRecPtr lsn, bool committed,
                char *error, size_t size)
{
    AuditCatalogInput input = {0};
    AuditCatalogDeltaList deltas;
    if (!d->catalog)
        return true;
    input.xid = xid;
    input.outcome = committed ? AUDIT_CATALOG_TX_COMMIT :
                                AUDIT_CATALOG_TX_ABORT;
    input.outcome_lsn = lsn;
    if (!audit_catalog_process(d->catalog, &input, &deltas, error, size))
        return false;
    for (size_t i = 0; i < deltas.count; i++)
    {
        AuditCatalogDelta *delta = &deltas.items[i];
        if (!selected_lsn(d, delta->event_lsn))
            continue;
        bson_t *event = catalog_event(d, delta);
        if (!event)
        {
            audit_catalog_delta_list_free(&deltas);
            return error_message(error, size,
                                 "out of memory creating catalog event");
        }
        if (!buffer_event(d, root, delta->event_lsn, event, error, size))
        {
            audit_catalog_delta_list_free(&deltas);
            return false;
        }
    }
    audit_catalog_delta_list_free(&deltas);
    return true;
}

static bool
resolve_transaction(AuditDecoder *d, TransactionId xid, TransactionId *children,
                    int nchildren, XLogRecPtr lsn, TimestampTz timestamp,
                    bool committed, char *error, size_t size)
{
    Transaction *root = get_transaction(d, xid, error, size);
    bool emit_effects = committed || d->options.include_aborted;
    const char *outcome = committed ? "committed" : "aborted";
    if (!root)
        return false;
    bool subtransaction = root->parent != 0;
    bool selected = !d->options.transaction_filter ||
                    descends_from(d, root, d->options.transaction_filter);
    if (subtransaction && committed)
        return error_message(error, size, "unexpected standalone commit for known subtransaction");
    for (int i = 0; i < nchildren; i++)
    {
        TransactionId child;
        memcpy(&child, (char *)children + i * sizeof(child), sizeof(child));
        if (!assign_parent(d, child, xid, error, size))
            return false;
    }
    for (Transaction *t = d->transactions; t; t = t->next)
        if (descends_from(d, t, xid))
        {
            if (t->xid == d->options.transaction_filter)
                selected = true;
            if (t->spill)
            {
                t->spill_remaining = t->event_count;
                if (!spill_peek(t, error, size))
                    return false;
            }
        }
    if (!resolve_catalog(d, root, xid, lsn, committed,
                         error, size))
        return false;
    if (selected && emit_effects)
    {
        for (;;)
        {
            Transaction *earliest = NULL;
            XLogRecPtr earliest_lsn = UINT64_MAX;
            for (Transaction *t = d->transactions; t; t = t->next)
            {
                XLogRecPtr event_lsn;
                if (!descends_from(d, t, xid) ||
                    (t->spill ? !t->spill_remaining : !t->head))
                    continue;
                event_lsn = t->spill ? t->spill_lsn : t->head->lsn;
                if (!earliest || event_lsn < earliest_lsn)
                {
                    earliest = t;
                    earliest_lsn = event_lsn;
                }
            }
            if (!earliest)
                break;
            bson_t *body = take_event(d, earliest, error, size);
            if (!body)
                return false;
            if (subtransaction &&
                !BSON_APPEND_INT64(body, "parentTransactionId", root->parent))
            {
                bson_destroy(body);
                return error_message(error, size, "cannot attach subtransaction parent");
            }
            bson_iter_t certainty;
            if (bson_iter_init_find(&certainty, body, "certainty") &&
                BSON_ITER_HOLDS_UTF8(&certainty) &&
                !strcmp(bson_iter_utf8(&certainty, NULL), "incomplete"))
                d->incomplete = true;
            bool ok = event_with_outcome(d, body, xid, lsn, timestamp, outcome);
            bson_destroy(body);
            if (!ok)
                return error_message(error, size, "event output failed");
        }
    }
    if (!subtransaction && selected && selected_lsn(d, lsn))
    {
        bson_t *summary = new_event(d, xid, lsn, "transaction", NULL, "certain", NULL);
        if (!summary || !event_with_outcome(d, summary, xid, lsn, timestamp, outcome))
        {
            if (summary)
                bson_destroy(summary);
            return error_message(error, size, "transaction output failed");
        }
        bson_destroy(summary);
    }
    /* Mark first: deleting parent state must not hide descendants. */
    for (Transaction *t = d->transactions; t; t = t->next)
        if (descends_from(d, t, xid))
            t->parent = xid;
    Transaction **link = &d->transactions;
    while (*link)
    {
        Transaction *t = *link;
        if (t->xid == xid || t->parent == xid)
        {
            *link = t->next;
            if (!free_transaction(d, t))
                return error_message(error, size, "cannot remove transaction spill file");
        }
        else
            link = &t->next;
    }
    return true;
}

static bool
consume(const char **cursor, size_t *remaining, size_t bytes)
{
    if (bytes > *remaining)
        return false;
    *cursor += bytes;
    *remaining -= bytes;
    return true;
}

static bool
counted(const char **cursor, size_t *remaining, size_t item_size)
{
    int32 count;
    if (*remaining < sizeof(count))
        return false;
    memcpy(&count, *cursor, sizeof(count));
    if (count < 0 || !consume(cursor, remaining, sizeof(count)) ||
        (size_t)count > *remaining / item_size)
        return false;
    return consume(cursor, remaining, (size_t)count * item_size);
}

static bool
validate_outcome(uint8 info, const char *data, size_t length, bool commit)
{
    uint32 flags = 0;
    const uint32 known = XACT_XINFO_HAS_DBINFO | XACT_XINFO_HAS_SUBXACTS |
        XACT_XINFO_HAS_RELFILELOCATORS | XACT_XINFO_HAS_INVALS |
        XACT_XINFO_HAS_TWOPHASE | XACT_XINFO_HAS_ORIGIN |
        XACT_XINFO_HAS_AE_LOCKS | XACT_XINFO_HAS_GID |
        XACT_XINFO_HAS_DROPPED_STATS | XACT_COMPLETION_APPLY_FEEDBACK |
        XACT_COMPLETION_UPDATE_RELCACHE_FILE | XACT_COMPLETION_FORCE_SYNC_COMMIT;
    if (!consume(&data, &length, sizeof(TimestampTz)))
        return false;
    if (info & XLOG_XACT_HAS_INFO)
    {
        if (length < sizeof(flags))
            return false;
        memcpy(&flags, data, sizeof(flags));
        if (!consume(&data, &length, sizeof(flags)) || (flags & ~known))
            return false;
    }
    if ((flags & XACT_XINFO_HAS_GID) && !(flags & XACT_XINFO_HAS_TWOPHASE))
        return false;
    if (!commit && (flags & XACT_XINFO_HAS_INVALS))
        return false;
    if ((flags & XACT_XINFO_HAS_DBINFO) &&
        !consume(&data, &length, sizeof(xl_xact_dbinfo)))
        return false;
    if ((flags & XACT_XINFO_HAS_SUBXACTS) &&
        !counted(&data, &length, sizeof(TransactionId)))
        return false;
    if ((flags & XACT_XINFO_HAS_RELFILELOCATORS) &&
        !counted(&data, &length, sizeof(RelFileLocator)))
        return false;
    if ((flags & XACT_XINFO_HAS_DROPPED_STATS) &&
        !counted(&data, &length, sizeof(xl_xact_stats_item)))
        return false;
    if ((flags & XACT_XINFO_HAS_INVALS) &&
        !counted(&data, &length, sizeof(SharedInvalidationMessage)))
        return false;
    if ((flags & XACT_XINFO_HAS_TWOPHASE) &&
        !consume(&data, &length, sizeof(xl_xact_twophase)))
        return false;
    if (flags & XACT_XINFO_HAS_GID)
    {
        const char *end = memchr(data, 0, length);
        if (!end || (size_t)(end - data) >= GIDSIZE ||
            !consume(&data, &length, end - data + 1))
            return false;
    }
    if ((flags & XACT_XINFO_HAS_ORIGIN) &&
        !consume(&data, &length, sizeof(xl_xact_origin)))
        return false;
    return length == 0;
}

static bool
close_relations(AuditDecoder *d, RelFileLocator *locators, int count,
                XLogRecPtr lsn, char *error, size_t size)
{
    if (!d->page_state)
        return true;
    for (int i = 0; i < count; i++)
    {
        const AuditRelation *relation = audit_manifest_relation(&d->manifest,
            locators[i].spcOid, locators[i].dbOid, locators[i].relNumber, lsn);
        if (!relation)
            continue;
        AuditRelationGeneration generation = page_relation(relation);
        if (!audit_page_state_relation_close(d->page_state, &generation, lsn,
                                              error, size))
            return false;
    }
    return true;
}

static bool
process_smgr(AuditDecoder *d, XLogReaderState *reader,
             Transaction *t, char *error, size_t size)
{
    uint8 info = XLogRecGetInfo(reader) & ~XLR_INFO_MASK;
    const char *data = XLogRecGetData(reader);
    size_t length = XLogRecGetDataLen(reader);
    RelFileLocator locator;
    ForkNumber fork;
    BlockNumber first_removed = 0;
    if (info == XLOG_SMGR_CREATE)
    {
        xl_smgr_create record;
        if (length != sizeof(record))
            return error_message(error, size,
                                 "malformed relation create record");
        memcpy(&record, data, sizeof(record));
        locator = record.rlocator;
        fork = record.forkNum;
    }
    else if (info == XLOG_SMGR_TRUNCATE)
    {
        xl_smgr_truncate record;
        if (length != sizeof(record))
            return error_message(error, size,
                                 "malformed relation truncate record");
        memcpy(&record, data, sizeof(record));
        locator = record.rlocator;
        fork = MAIN_FORKNUM;
        first_removed = record.blkno;
        if (!(record.flags & SMGR_TRUNCATE_HEAP))
            return physical_event(d, reader, t, NULL, error, size);
    }
    else
        return physical_event(d, reader, t, NULL, error, size);
    const AuditRelation *relation = audit_manifest_relation(&d->manifest,
        locator.spcOid, locator.dbOid, locator.relNumber, reader->ReadRecPtr);
    if (!relation || fork != MAIN_FORKNUM || !d->page_state)
        return physical_event(d, reader, t, NULL, error, size);
    AuditRelationGeneration generation = page_relation(relation);
    if (info == XLOG_SMGR_CREATE)
    {
        if (!audit_page_state_relation_create(d->page_state, &generation,
                reader->ReadRecPtr, error, size))
            return false;
    }
    else if (!audit_page_state_truncate(d->page_state, &generation,
                 first_removed, reader->ReadRecPtr, error, size))
        return false;
    return physical_event(d, reader, t, NULL, error, size);
}

static bool
process_xact(AuditDecoder *d, XLogReaderState *reader, char *error, size_t size)
{
    uint8 info = XLogRecGetInfo(reader);
    uint8 opcode = info & XLOG_XACT_OPMASK;
    TransactionId xid = XLogRecGetXid(reader);
    char *data = XLogRecGetData(reader);
    size_t length = XLogRecGetDataLen(reader);
    if (opcode == XLOG_XACT_ASSIGNMENT)
    {
        xl_xact_assignment assignment;
        if (length < MinSizeOfXactAssignment)
            return error_message(error, size, "truncated subtransaction assignment");
        memset(&assignment, 0, sizeof(assignment));
        memcpy(&assignment, data, MinSizeOfXactAssignment);
        if (assignment.nsubxacts < 0 ||
            (size_t)assignment.nsubxacts != (length - MinSizeOfXactAssignment) / sizeof(TransactionId) ||
            (length - MinSizeOfXactAssignment) % sizeof(TransactionId))
            return error_message(error, size, "invalid subtransaction assignment");
        for (int i = 0; i < assignment.nsubxacts; i++)
        {
            TransactionId child;
            memcpy(&child, data + MinSizeOfXactAssignment + i * sizeof(child), sizeof(child));
            if (!assign_parent(d, child, assignment.xtop, error, size))
                return false;
        }

        return true;
    }
    if (opcode == XLOG_XACT_COMMIT || opcode == XLOG_XACT_COMMIT_PREPARED)
    {
        xl_xact_parsed_commit parsed;
        if (!validate_outcome(info, data, length, true))
            return error_message(error, size, "malformed commit record");
        ParseCommitRecord(info, (xl_xact_commit *)data, &parsed);
        if (opcode == XLOG_XACT_COMMIT_PREPARED)
        {
            if (!parsed.twophase_xid)
                return error_message(error, size, "prepared commit missing original transaction XID");
            xid = parsed.twophase_xid;
        }
        if (!close_relations(d, parsed.xlocators, parsed.nrels,
                             reader->ReadRecPtr, error, size))
            return false;
        return resolve_transaction(d, xid, parsed.subxacts, parsed.nsubxacts,
             reader->ReadRecPtr, parsed.xact_time, true, error, size);
    }
    if (opcode == XLOG_XACT_ABORT || opcode == XLOG_XACT_ABORT_PREPARED)
    {
        xl_xact_parsed_abort parsed;
        if (!validate_outcome(info, data, length, false))
            return error_message(error, size, "malformed abort record");
        ParseAbortRecord(info, (xl_xact_abort *)data, &parsed);
        if (opcode == XLOG_XACT_ABORT_PREPARED)
        {
            if (!parsed.twophase_xid)
                return error_message(error, size, "prepared abort missing original transaction XID");
            xid = parsed.twophase_xid;
        }
        if (!close_relations(d, parsed.xlocators, parsed.nrels,
                             reader->ReadRecPtr, error, size))
            return false;
        return resolve_transaction(d, xid, parsed.subxacts, parsed.nsubxacts,
             reader->ReadRecPtr, parsed.xact_time, false, error, size);
    }
    if (opcode == XLOG_XACT_PREPARE)
    {
        xl_xact_prepare prepare;
        xl_xact_parsed_prepare parsed;
        if (length < sizeof(prepare))
            return error_message(error, size, "truncated prepared transaction record");
        memcpy(&prepare, data, sizeof(prepare));
        if (!prepare.xid || prepare.nsubxacts < 0 ||
            prepare.ncommitrels < 0 || prepare.nabortrels < 0 ||
            prepare.ncommitstats < 0 || prepare.nabortstats < 0 ||
            prepare.ninvalmsgs < 0 || prepare.gidlen == 0 ||
            prepare.gidlen > GIDSIZE)
            return error_message(error, size, "invalid prepared transaction header");
        size_t offset = MAXALIGN(sizeof(prepare));
        size_t gidbytes = MAXALIGN(prepare.gidlen);
        size_t childbytes = (size_t)prepare.nsubxacts * sizeof(TransactionId);
        if (offset > length || gidbytes > length - offset ||
            childbytes > length - offset - gidbytes ||
            data[offset + prepare.gidlen - 1] != 0)
            return error_message(error, size, "truncated prepared transaction children");
        const char *cursor = data + offset + gidbytes;
        size_t remaining = length - offset - gidbytes;
        const int counts[] = {prepare.nsubxacts, prepare.ncommitrels, prepare.nabortrels,
                              prepare.ncommitstats, prepare.nabortstats, prepare.ninvalmsgs};
        const size_t sizes[] = {sizeof(TransactionId), sizeof(RelFileLocator), sizeof(RelFileLocator),
                               sizeof(xl_xact_stats_item), sizeof(xl_xact_stats_item),
                               sizeof(SharedInvalidationMessage)};
        for (size_t i = 0; i < lengthof(counts); i++)
            if ((size_t)counts[i] > remaining / sizes[i] ||
                !consume(&cursor, &remaining, MAXALIGN((size_t)counts[i] * sizes[i])))
                return error_message(error, size, "truncated prepared transaction metadata");
        ParsePrepareRecord(info, (xl_xact_prepare *)data, &parsed);
        if (!get_transaction(d, parsed.twophase_xid, error, size))
            return false;
        for (int i = 0; i < parsed.nsubxacts; i++)
        {
            TransactionId child;
            memcpy(&child, (char *)parsed.subxacts + i * sizeof(child), sizeof(child));
            if (!assign_parent(d, child, parsed.twophase_xid, error, size))
                return false;
        }
    }
    return true;
}

static bool
physical_event(AuditDecoder *d, XLogReaderState *reader, Transaction *t,
               const char *warning, char *error, size_t size)
{
    if (!d->options.show_postgres_records || !selected_lsn(d, reader->ReadRecPtr))
        return true;
    bson_t *event = new_event(d, XLogRecGetXid(reader), reader->ReadRecPtr,
                             "postgresRecord", NULL, "physical", warning);
    if (!event)
        return error_message(error, size, "out of memory creating physical record");
    BSON_APPEND_INT32(event, "resourceManager", XLogRecGetRmid(reader));
    BSON_APPEND_INT32(event, "recordInfo", XLogRecGetInfo(reader));
    BSON_APPEND_INT64(event, "recordBytes", XLogRecGetTotalLen(reader));
    BSON_APPEND_INT64(event, "mainDataBytes", XLogRecGetDataLen(reader));
    bson_t blocks;
    unsigned index = 0;
    BSON_APPEND_ARRAY_BEGIN(event, "blocks", &blocks);
    for (int block = 0; block <= XLR_MAX_BLOCK_ID; block++)
    {
        RelFileLocator locator;
        ForkNumber fork;
        BlockNumber page;
        bson_t entry;
        char key[16];
        Size length;
        if (!XLogRecHasBlockRef(reader, block))
            continue;
        XLogRecGetBlockTag(reader, block, &locator, &fork, &page);
        XLogRecGetBlockData(reader, block, &length);
        snprintf(key, sizeof(key), "%u", index++);
        BSON_APPEND_DOCUMENT_BEGIN(&blocks, key, &entry);
        BSON_APPEND_INT32(&entry, "blockId", block);
        BSON_APPEND_INT64(&entry, "tblspaceOid", locator.spcOid);
        BSON_APPEND_INT64(&entry, "databaseOid", locator.dbOid);
        BSON_APPEND_INT64(&entry, "relfilenode", locator.relNumber);
        BSON_APPEND_INT32(&entry, "fork", fork);
        BSON_APPEND_INT64(&entry, "block", page);
        BSON_APPEND_INT64(&entry, "dataBytes", length);
        BSON_APPEND_BOOL(&entry, "hasImage", XLogRecHasBlockImage(reader, block));
        bson_append_document_end(&blocks, &entry);
    }
    bson_append_array_end(event, &blocks);
    if (t)
        return buffer_event(d, t, reader->ReadRecPtr, event, error, size);
    if (d->options.transaction_filter)
    {
        bson_destroy(event);
        return true;
    }
    bool ok = output_event(&d->options, event);
    bson_destroy(event);
    return ok || error_message(error, size, "physical record output failed");
}

static bson_t *
document_event(AuditDecoder *d, XLogReaderState *reader, uint8 block,
               const char *operation, const AuditRelation *relation,
               const uint8 *before_data, size_t before_length,
               bool before_is_key,
               const uint8 *after_data, size_t after_length,
               const char *initial_warning)
{
    bson_t before, after, before_id, after_id, locator;
    bool have_before = false, have_after = false, have_before_id = false;
    char warning[256] = "";
    RelFileLocator rel;
    ForkNumber fork;
    BlockNumber page;
    if (initial_warning)
        snprintf(warning, sizeof(warning), "%s", initial_warning);
    if (before_data)
    {
        have_before = audit_tuple_decode(before_data, before_length, d->options.max_document_bytes,
                                        &before_id, &before, warning, sizeof(warning));
        have_before_id = have_before;
        if (!have_before && before_is_key &&
            audit_tuple_key_decode(before_data, before_length, d->options.max_document_bytes,
                                   &before_id, warning, sizeof(warning)))
        {
            have_before_id = true;
            snprintf(warning, sizeof(warning),
                     "before document is unavailable; only replica-identity key is logged");
        }
    }
    if (after_data)
        have_after = audit_tuple_decode(after_data, after_length, d->options.max_document_bytes,
                                       &after_id, &after, warning, sizeof(warning));
    if (!strcmp(operation, "insert") && !have_after && !*warning)
        snprintf(warning, sizeof(warning), "tuple bytes are unavailable (including full-page-image-only records)");
    if ((!strcmp(operation, "update") || !strcmp(operation, "delete")) && !have_before && !*warning)
        snprintf(warning, sizeof(warning), "before document is unavailable in physical WAL");
    if (!strcmp(operation, "update") && !have_after && !*warning)
        snprintf(warning, sizeof(warning), "after document is unavailable in physical WAL");
    bool incomplete = *warning != 0;
    bson_t *event = new_event(d, XLogRecGetXid(reader), reader->ReadRecPtr,
                 "document", operation, incomplete ? "incomplete" : "certain",
                 *warning ? warning : NULL);
    if (!event)
        return NULL;
    /* Replace null defaults without duplicate BSON keys. */
    bson_t result;
    bson_iter_t it;
    bson_init(&result);
    bson_iter_init(&it, event);
    while (bson_iter_next(&it))
    {
        const char *key = bson_iter_key(&it);
        if (!strcmp(key, "relation"))
            continue;
        else if (!strcmp(key, "database"))
            BSON_APPEND_UTF8(&result, key, relation->database);
        else if (!strcmp(key, "collection"))
            BSON_APPEND_UTF8(&result, key, relation->collection);
        else if (!strcmp(key, "collectionId"))
            BSON_APPEND_INT64(&result, key, relation->collection_id);
        else if (!strcmp(key, "objectId") && !d->options.redact_documents && (have_after || have_before_id))
        {
            bson_t normalized_id;
            bson_iter_t id;
            bson_iter_init_find(&id, have_after ? &after_id : &before_id, "");
            BSON_APPEND_DOCUMENT_BEGIN(&result, key, &normalized_id);
            bson_append_value(&normalized_id, "_id", 3, bson_iter_value(&id));
            bson_append_document_end(&result, &normalized_id);
        }
        else if (!strcmp(key, "before") && !d->options.redact_documents && have_before)
            BSON_APPEND_DOCUMENT(&result, key, &before);
        else if (!strcmp(key, "after") && !d->options.redact_documents && have_after)
            BSON_APPEND_DOCUMENT(&result, key, &after);
        else
            bson_append_value(&result, key, -1, bson_iter_value(&it));
    }
    XLogRecGetBlockTag(reader, block, &rel, &fork, &page);
    BSON_APPEND_DOCUMENT_BEGIN(&result, "relation", &locator);
    BSON_APPEND_INT64(&locator, "tblspaceOid", rel.spcOid);
    BSON_APPEND_INT64(&locator, "databaseOid", rel.dbOid);
    BSON_APPEND_INT64(&locator, "relfilenode", rel.relNumber);
    BSON_APPEND_INT64(&locator, "block", page);
    bson_append_document_end(&result, &locator);
    bson_destroy(event);
    event = bson_copy(&result);
    bson_destroy(&result);
    return event;
}

static bool
stage_catalog(AuditDecoder *d, XLogReaderState *reader,
              const AuditRelation *relation,
              AuditCatalogHeapOperation operation, uint32 ordinal,
              BlockNumber old_block, OffsetNumber old_offset,
              BlockNumber new_block, OffsetNumber new_offset,
              const uint8 *old_tuple, size_t old_length,
              const uint8 *new_tuple, size_t new_length,
              char *error, size_t size)
{
    AuditCatalogInput input = {0};
    AuditCatalogDeltaList ignored;
    if (!d->catalog)
        return error_message(error, size,
                             "catalog relation requires initialized catalog state");
    input.relation.tablespace = relation->tablespace;
    input.relation.database_oid = relation->database_oid;
    input.relation.relfilenode = relation->relfilenode;
    input.operation = operation;
    input.outcome = AUDIT_CATALOG_TX_PENDING;
    input.xid = XLogRecGetXid(reader);
    input.record_lsn = reader->ReadRecPtr;
    input.operation_ordinal = ordinal;
    input.old_tid = (AuditCatalogTid){old_block, old_offset,
                                      OffsetNumberIsValid(old_offset)};
    input.new_tid = (AuditCatalogTid){new_block, new_offset,
                                      OffsetNumberIsValid(new_offset)};
    input.old_tuple = old_tuple;
    input.old_tuple_length = old_length;
    input.new_tuple = new_tuple;
    input.new_tuple_length = new_length;
    if (!input.xid)
        return error_message(error, size,
                             "catalog heap effect has no transaction XID");
    return audit_catalog_process(d->catalog, &input, &ignored, error, size);
}

static bool
process_heap(AuditDecoder *d, XLogReaderState *reader, Transaction *t,
             char *error, size_t size)
{
    RelFileLocator locator;
    ForkNumber fork;
    BlockNumber page;
    const AuditRelation *relation;
    uint8 info = XLogRecGetInfo(reader) & XLOG_HEAP_OPMASK;
    uint8 rmid = XLogRecGetRmid(reader);
    const char *main = XLogRecGetData(reader);
    size_t main_length = XLogRecGetDataLen(reader), before_length = 0;
    Size after_length = 0;
    const uint8 *before = NULL, *after = NULL;
    const char *operation = "unknown";
    const char *warning = NULL;
    bool before_is_key = false;
    bool emit_document;
    uint8 block = 0;
    if (!XLogRecHasBlockRef(reader, block))
        return physical_event(d, reader, t, NULL, error, size);
    XLogRecGetBlockTag(reader, block, &locator, &fork, &page);
    relation = audit_manifest_relation(&d->manifest, locator.spcOid, locator.dbOid,
                                       locator.relNumber, reader->ReadRecPtr);
    if (!relation || fork != MAIN_FORKNUM)
    {
        const AuditRelation *known = audit_manifest_relation(&d->manifest,
            locator.spcOid, locator.dbOid, locator.relNumber, d->manifest.from);
        if (known && !relation && selected_lsn(d, reader->ReadRecPtr))
        {
            bson_t *event = new_event(d, XLogRecGetXid(reader), reader->ReadRecPtr,
                         "postgresRecord", NULL, "incomplete",
                         "relation manifest is not valid at event LSN; no namespace mapping applied");
            if (!event)
                return error_message(error, size, "out of memory creating incomplete event");
            if (t)
                return buffer_event(d, t, reader->ReadRecPtr, event, error, size);
            d->incomplete = true;
            bool ok = output_event(&d->options, event);
            bson_destroy(event);
            return ok || error_message(error, size, "incomplete event output failed");
        }
        return physical_event(d, reader, t, NULL, error, size);
    }
    emit_document = relation->kind != AUDIT_RELATION_DOCUMENT ||
                    selected_lsn(d, reader->ReadRecPtr);
    if (relation->kind == AUDIT_RELATION_DOCUMENT)
    {
        if (!apply_block_image(d, reader, 0, relation, error, size))
            return false;
        if (XLogRecHasBlockRef(reader, 1) &&
            !apply_block_image(d, reader, 1, relation, error, size))
            return false;
    }
    if (rmid == RM_HEAP2_ID && info == XLOG_HEAP2_MULTI_INSERT)
    {
        xl_heap_multi_insert multi;
        Size bytes;
        const uint8 *tuples = (const uint8 *)XLogRecGetBlockData(reader, 0, &bytes);
        size_t position = 0;
        if (main_length < SizeOfHeapMultiInsert)
            return error_message(error, size, "truncated heap multi-insert");
        memset(&multi, 0, sizeof(multi));
        memcpy(&multi, main, SizeOfHeapMultiInsert);
        if (!multi.ntuples || (!(XLogRecGetInfo(reader) & XLOG_HEAP_INIT_PAGE) &&
            main_length - SizeOfHeapMultiInsert != multi.ntuples * sizeof(OffsetNumber)))
            return error_message(error, size, "invalid heap multi-insert count");
        if (!t)
            return error_message(error, size, "heap multi-insert has no transaction XID");
        if (!tuples)
        {
            if (relation->kind == AUDIT_RELATION_COLLECTIONS_CATALOG)
                return stage_catalog(d, reader, relation,
                    AUDIT_CATALOG_HEAP_INSERT, 0, 0, InvalidOffsetNumber,
                    page, InvalidOffsetNumber, NULL, 0, NULL, 0, error, size);
            bson_t *event = document_event(d, reader, 0, "insert", relation,
                    NULL, 0, false, NULL, 0, "multi-insert tuple bytes unavailable (full-page image is not extracted)");
            if (!event)
                return error_message(error, size, "out of memory creating multi-insert event");
            BSON_APPEND_INT32(event, "tupleCount", multi.ntuples);
            return buffer_event(d, t, reader->ReadRecPtr, event, error, size);
        }
        for (unsigned i = 0; i < multi.ntuples; i++)
        {
            xl_multi_insert_tuple tuple;
            xl_heap_header header;
            uint8 *reconstructed;
            bson_t *event;
            position = SHORTALIGN(position);
            if (position > bytes || bytes - position < SizeOfMultiInsertTuple)
                return error_message(error, size, "truncated multi-insert tuple header");
            memset(&tuple, 0, sizeof(tuple));
            memcpy(&tuple, tuples + position, SizeOfMultiInsertTuple);
            position += SizeOfMultiInsertTuple;
            if (tuple.datalen > bytes - position)
                return error_message(error, size, "truncated multi-insert tuple data");
            memset(&header, 0, sizeof(header));
            header.t_infomask2 = tuple.t_infomask2;
            header.t_infomask = tuple.t_infomask;
            header.t_hoff = tuple.t_hoff;
            reconstructed = malloc(SizeOfHeapHeader + tuple.datalen);
            if (!reconstructed)
                return error_message(error, size, "out of memory reconstructing multi-insert tuple");
            memcpy(reconstructed, &header, SizeOfHeapHeader);
            memcpy(reconstructed + SizeOfHeapHeader, tuples + position, tuple.datalen);
            position += tuple.datalen;
            if (relation->kind == AUDIT_RELATION_COLLECTIONS_CATALOG)
            {
                OffsetNumber offnum;
                if (XLogRecGetInfo(reader) & XLOG_HEAP_INIT_PAGE)
                    offnum = FirstOffsetNumber + i;
                else
                    memcpy(&offnum, main + SizeOfHeapMultiInsert +
                           i * sizeof(offnum), sizeof(offnum));
                bool staged = stage_catalog(d, reader, relation,
                    AUDIT_CATALOG_HEAP_INSERT, i, 0, InvalidOffsetNumber,
                    page, offnum, NULL, 0, reconstructed,
                    SizeOfHeapHeader + tuple.datalen, error, size);
                free(reconstructed);
                if (!staged)
                    return false;
                continue;
            }
            if (d->page_state)
            {
                AuditPhysicalTid tid = {
                    page,
                    (XLogRecGetInfo(reader) & XLOG_HEAP_INIT_PAGE) ?
                        FirstOffsetNumber + i : InvalidOffsetNumber
                };
                if (!(XLogRecGetInfo(reader) & XLOG_HEAP_INIT_PAGE))
                    memcpy(&tid.offset, main + SizeOfHeapMultiInsert +
                           i * sizeof(OffsetNumber), sizeof(OffsetNumber));
                uint8 *full = NULL;
                size_t full_length = 0;
                AuditRelationGeneration generation = page_relation(relation);
                if (!full_heap_tuple(reconstructed,
                                     SizeOfHeapHeader + tuple.datalen,
                                     XLogRecGetXid(reader), tid,
                                     &full, &full_length, error, size) ||
                    !audit_page_state_relation_create(d->page_state, &generation,
                        reader->ReadRecPtr, error, size) ||
                    !audit_page_state_heap_insert(d->page_state, &generation, tid,
                        full, full_length, AUDIT_PAGE_ORIGIN_PROVED,
                        AUDIT_STATE_SOURCE_WAL_TUPLE, reader->ReadRecPtr,
                        error, size))
                {
                    free(full);
                    free(reconstructed);
                    return false;
                }
                free(full);
            }
            if (!emit_document)
            {
                free(reconstructed);
                continue;
            }
            event = document_event(d, reader, 0, "insert", relation,
                         NULL, 0, false, reconstructed, SizeOfHeapHeader + tuple.datalen, NULL);
            free(reconstructed);
            if (!event)
                return error_message(error, size, "out of memory creating multi-insert event");
            if (!buffer_event(d, t, reader->ReadRecPtr, event, error, size))
                return false;
        }
        if (position != bytes)
            return error_message(error, size, "unexpected multi-insert trailing data");
        return true;
    }
    if (rmid == RM_HEAP_ID && info == XLOG_HEAP_INSERT)
    {
        xl_heap_insert insert;
        if (main_length < SizeOfHeapInsert)
            return error_message(error, size, "truncated heap insert");
        memset(&insert, 0, sizeof(insert));
        memcpy(&insert, main, SizeOfHeapInsert);
        operation = "insert";
        after = (const uint8 *)XLogRecGetBlockData(reader, 0, &after_length);
        if (relation->kind == AUDIT_RELATION_COLLECTIONS_CATALOG)
            return stage_catalog(d, reader, relation,
                AUDIT_CATALOG_HEAP_INSERT, 0, 0, InvalidOffsetNumber,
                page, insert.offnum, NULL, 0, after, after_length,
                error, size);
        if (after && d->page_state)
        {
            AuditPhysicalTid tid = {page, insert.offnum};
            AuditRelationGeneration generation = page_relation(relation);
            uint8 *full = NULL;
            size_t full_length = 0;
            if (!full_heap_tuple(after, after_length, XLogRecGetXid(reader),
                                 tid, &full, &full_length, error, size) ||
                !audit_page_state_relation_create(d->page_state, &generation,
                    reader->ReadRecPtr, error, size) ||
                !audit_page_state_heap_insert(d->page_state, &generation, tid,
                    full, full_length, AUDIT_PAGE_ORIGIN_PROVED,
                    AUDIT_STATE_SOURCE_WAL_TUPLE, reader->ReadRecPtr,
                    error, size))
            {
                free(full);
                return false;
            }
            free(full);
        }
    }
    else if (rmid == RM_HEAP_ID && (info == XLOG_HEAP_UPDATE || info == XLOG_HEAP_HOT_UPDATE))
    {
        xl_heap_update update;
        if (main_length < SizeOfHeapUpdate)
            return error_message(error, size, "truncated heap update");
        memset(&update, 0, sizeof(update));
        memcpy(&update, main, SizeOfHeapUpdate);
        operation = "update";
        after = (const uint8 *)XLogRecGetBlockData(reader, 0, &after_length);
        if (update.flags & (XLH_UPDATE_CONTAINS_OLD_TUPLE | XLH_UPDATE_CONTAINS_OLD_KEY))
        {
            before = (const uint8 *)main + SizeOfHeapUpdate;
            before_length = main_length - SizeOfHeapUpdate;
            before_is_key = (update.flags & XLH_UPDATE_CONTAINS_OLD_KEY) != 0;
        }
        if (relation->kind == AUDIT_RELATION_COLLECTIONS_CATALOG)
        {
            BlockNumber old_page = page;
            if (XLogRecHasBlockRef(reader, 1))
            {
                RelFileLocator old_locator;
                ForkNumber old_fork;
                XLogRecGetBlockTag(reader, 1, &old_locator, &old_fork,
                                   &old_page);
                if (old_fork != MAIN_FORKNUM ||
                    old_locator.spcOid != locator.spcOid ||
                    old_locator.dbOid != locator.dbOid ||
                    old_locator.relNumber != locator.relNumber)
                    return error_message(error, size,
                                         "catalog update old block relation mismatch");
            }
            return stage_catalog(d, reader, relation,
                AUDIT_CATALOG_HEAP_UPDATE, 0, old_page, update.old_offnum,
                page, update.new_offnum, before, before_length, after,
                after_length, error, size);
        }
        if (d->page_state && after)
        {
            BlockNumber old_page = page;
            AuditUpdateReconstruction reconstructed;
            AuditRelationGeneration generation = page_relation(relation);
            if (XLogRecHasBlockRef(reader, 1))
            {
                RelFileLocator old_locator;
                ForkNumber old_fork;
                XLogRecGetBlockTag(reader, 1, &old_locator, &old_fork,
                                   &old_page);
                if (old_fork != MAIN_FORKNUM ||
                    old_locator.spcOid != locator.spcOid ||
                    old_locator.dbOid != locator.dbOid ||
                    old_locator.relNumber != locator.relNumber)
                    return error_message(error, size,
                                        "heap update old block relation mismatch");
            }
            AuditUpdateReconstructionInput input = {
                .old_relation = generation,
                .new_relation = generation,
                .old_tid = {old_page, update.old_offnum},
                .new_tid = {page, update.new_offnum},
                .xid = XLogRecGetXid(reader),
                .new_xmax = update.new_xmax,
                .record_lsn = reader->ReadRecPtr,
                .hot_update = info == XLOG_HEAP_HOT_UPDATE,
                .new_tuple_trust = AUDIT_PAGE_ORIGIN_PROVED,
                .prefix_from_old =
                    (update.flags & XLH_UPDATE_PREFIX_FROM_OLD) != 0,
                .suffix_from_old =
                    (update.flags & XLH_UPDATE_SUFFIX_FROM_OLD) != 0,
                .block_data = after,
                .block_data_length = after_length
            };
            if (!audit_page_state_relation_create(d->page_state, &generation,
                    reader->ReadRecPtr, error, size) ||
                !audit_reconstruct_heap_update(d->page_state, &input,
                                               &reconstructed, error, size))
                return false;
            if (reconstructed.status == AUDIT_RECONSTRUCTION_EXACT)
            {
                after = reconstructed.after_decoder_tuple;
                after_length = reconstructed.after_decoder_tuple_length;
                warning = NULL;
            }
            else
            {
                warning = reconstructed.warning;
                after = NULL;
                after_length = 0;
            }
            bson_t *event = NULL;
            if (emit_document)
                event = document_event(d, reader, block, operation, relation,
                    before, before_length, before_is_key, after, after_length,
                    warning);
            if (event)
            {
                bson_t provenance;
                BSON_APPEND_DOCUMENT_BEGIN(event, "reconstruction", &provenance);
                BSON_APPEND_UTF8(&provenance, "method",
                    reconstructed.provenance.method);
                BSON_APPEND_BOOL(&provenance, "usedPrefix",
                    reconstructed.provenance.used_prefix);
                BSON_APPEND_BOOL(&provenance, "usedSuffix",
                    reconstructed.provenance.used_suffix);
                BSON_APPEND_INT32(&provenance, "prefixBytes",
                    reconstructed.provenance.prefix_length);
                BSON_APPEND_INT32(&provenance, "suffixBytes",
                    reconstructed.provenance.suffix_length);
                append_lsn(&provenance, "baseAppliedLsn",
                    reconstructed.provenance.base_applied_lsn);
                bson_append_document_end(event, &provenance);
            }
            audit_update_reconstruction_free(&reconstructed);
            if (!emit_document)
                return true;
            if (!event)
                return error_message(error, size,
                                     "out of memory creating document event");
            if (!t)
            {
                bson_destroy(event);
                return error_message(error, size,
                                     "heap effect has no transaction XID");
            }
            return buffer_event(d, t, reader->ReadRecPtr, event, error, size);
        }
        if (!d->page_state &&
            (update.flags &
             (XLH_UPDATE_PREFIX_FROM_OLD | XLH_UPDATE_SUFFIX_FROM_OLD)))
        {
            warning = "update base state is unavailable";
            after = NULL;
            after_length = 0;
        }
    }
    else if (rmid == RM_HEAP_ID && info == XLOG_HEAP_DELETE)
    {
        xl_heap_delete delete;
        if (main_length < SizeOfHeapDelete)
            return error_message(error, size, "truncated heap delete");
        memset(&delete, 0, sizeof(delete));
        memcpy(&delete, main, SizeOfHeapDelete);
        operation = "delete";
        if (delete.flags & (XLH_DELETE_CONTAINS_OLD_TUPLE | XLH_DELETE_CONTAINS_OLD_KEY))
        {
            before = (const uint8 *)main + SizeOfHeapDelete;
            before_length = main_length - SizeOfHeapDelete;
            before_is_key = (delete.flags & XLH_DELETE_CONTAINS_OLD_KEY) != 0;
        }
        if (relation->kind == AUDIT_RELATION_COLLECTIONS_CATALOG)
            return stage_catalog(d, reader, relation,
                AUDIT_CATALOG_HEAP_DELETE, 0, page, delete.offnum,
                0, InvalidOffsetNumber, before, before_length, NULL, 0,
                error, size);
        if (d->page_state)
        {
            AuditRelationGeneration generation = page_relation(relation);
            AuditPhysicalTid tid = {page, delete.offnum};
            if (!audit_page_state_relation_create(d->page_state, &generation,
                    reader->ReadRecPtr, error, size) ||
                !audit_page_state_heap_delete(d->page_state, &generation, tid,
                    reader->ReadRecPtr, error, size))
                return false;
        }
    }
    else
        return physical_event(d, reader, t, NULL, error, size);
    if (!emit_document)
        return true;
    bson_t *event = document_event(d, reader, block, operation, relation, before,
                                   before_length, before_is_key, after, after_length, warning);
    if (!event)
        return error_message(error, size, "out of memory creating document event");
    if (!t)
    {
        bson_destroy(event);
        return error_message(error, size, "heap effect has no transaction XID");
    }
    return buffer_event(d, t, reader->ReadRecPtr, event, error, size);
}

AuditDecoder *
audit_decoder_create(const AuditOptions *options, char *error, size_t size)
{
    AuditDecoder *d = calloc(1, sizeof(*d));
    if (!d)
    {
        error_message(error, size, "out of memory creating decoder");
        return NULL;
    }
    d->options = *options;
    if (!d->options.max_transaction_bytes)
        d->options.max_transaction_bytes = 64U * 1024U * 1024U;
    if (!d->options.max_document_bytes)
        d->options.max_document_bytes = 16U * 1024U * 1024U;
    if (options->manifest_path &&
        !audit_manifest_load(options->manifest_path, &d->manifest, error, size))
        goto invalid;
    if (options->manifest_path &&
        ((options->system_identifier && options->system_identifier != d->manifest.system_identifier) ||
         (options->timeline && options->timeline != d->manifest.timeline)))
    {
        error_message(error, size, "manifest systemIdentifier/timeline does not match WAL");
        goto invalid;
    }
    if (options->spill_dir)
    {
        struct stat st;
        if (lstat(options->spill_dir, &st) || !S_ISDIR(st.st_mode) ||
            st.st_uid != geteuid() || (st.st_mode & 0777) != 0700)
        {
            error_message(error, size, "--spill-dir must be a non-symlink directory owned by current user with mode 0700");
            goto invalid;
        }
    }
    bool has_catalog = false;
    for (size_t i = 0; i < d->manifest.count; i++)
        if (d->manifest.relations[i].kind ==
            AUDIT_RELATION_COLLECTIONS_CATALOG)
        {
            has_catalog = true;
            break;
        }
    if ((options->catalog_cache_path || options->ephemeral_cache_dir ||
         options->rebuild_cache || options->no_persistent_cache) &&
        (!options->manifest_path || d->manifest.schema_version != 2 ||
         !has_catalog))
    {
        error_message(error, size,
            "catalog cache options require a version 2 manifest with collections_catalog");
        goto invalid;
    }
    if (has_catalog)
    {
        AuditCatalogCacheConfig config = {0};
        AuditPageStateBackend backend;
        AuditPageStateConfig page_config = {
            .max_tuple_bytes = MaxHeapTupleSize,
            .max_offset_number = MaxOffsetNumber
        };
        config.mode = AUDIT_CATALOG_CACHE_EPHEMERAL;
        config.coverage = AUDIT_CATALOG_COVERAGE_ROW_LOCAL;
        config.system_identifier = d->manifest.system_identifier;
        config.postgres_major = PG_VERSION_NUM / 10000;
        config.block_size = BLCKSZ;
        config.wal_segment_size = options->wal_segment_size;
        config.timeline = d->manifest.timeline;
        config.documentdb_version = d->manifest.documentdb_version;
        if (options->catalog_cache_path)
        {
            config.path = options->catalog_cache_path;
            config.mode = options->rebuild_cache ?
                AUDIT_CATALOG_CACHE_REBUILD : AUDIT_CATALOG_CACHE_NORMAL;
        }
        else if (options->ephemeral_cache_dir)
        {
            struct stat st;
            size_t length;
            if (lstat(options->ephemeral_cache_dir, &st) ||
                !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) ||
                st.st_uid != geteuid() || (st.st_mode & 0777) != 0700)
            {
                error_message(error, size,
                    "--ephemeral-cache must be a non-symlink directory owned by current user with mode 0700");
                goto invalid;
            }
            length = strlen(options->ephemeral_cache_dir) + 64;
            d->ephemeral_catalog_path = malloc(length);
            if (!d->ephemeral_catalog_path)
            {
                error_message(error, size,
                              "out of memory creating ephemeral cache path");
                goto invalid;
            }
            snprintf(d->ephemeral_catalog_path, length,
                     "%s/catalog-%ld.sqlite",
                     options->ephemeral_cache_dir, (long)getpid());
            config.path = d->ephemeral_catalog_path;
            config.mode = AUDIT_CATALOG_CACHE_NORMAL;
        }
        d->catalog = audit_catalog_cache_open(&config, error, size);
        if (!d->catalog)
            goto invalid;
        if (!audit_catalog_page_state_backend(d->catalog, &backend,
                                              error, size))
            goto invalid;
        d->page_state = audit_page_state_create(&page_config, &backend,
                                                error, size);
        if (!d->page_state)
            goto invalid;
    }
    return d;
invalid:
    audit_decoder_destroy(d);
    return NULL;
}

bool
audit_decoder_process(AuditDecoder *d, XLogReaderState *reader, char *error, size_t size)
{
    TransactionId xid = XLogRecGetXid(reader);
    TransactionId top = XLogRecGetTopXid(reader);
    Transaction *t = NULL;
    bool ok;
    if (d->failed)
        return error_message(error, size, "decoder has already failed");
    if (top && xid && top != xid && !assign_parent(d, xid, top, error, size))
        goto invalid;
    if (XLogRecGetRmid(reader) == RM_XACT_ID)
        ok = process_xact(d, reader, error, size);
    else
    {
        if (xid && !(t = get_transaction(d, xid, error, size)))
            goto invalid;
        if (XLogRecGetRmid(reader) == RM_HEAP_ID ||
            XLogRecGetRmid(reader) == RM_HEAP2_ID)
            ok = process_heap(d, reader, t, error, size);
        else if (XLogRecGetRmid(reader) == RM_SMGR_ID)
            ok = process_smgr(d, reader, t, error, size);
        else
            ok = physical_event(d, reader, t, NULL, error, size);
    }
    if (!ok)
        goto invalid;
    return true;
invalid:
    d->failed = true;
    return false;
}

bool
audit_decoder_finish(AuditDecoder *d, char *error, size_t size)
{
    bool unresolved = d->transactions != NULL;
    Transaction *requested = d->options.transaction_filter ?
        find_transaction(d, d->options.transaction_filter) : NULL;
    if (d->failed)
        return error_message(error, size, "decoder failed before end of WAL");
    for (Transaction *t = d->transactions; t; t = t->next)
    {
        if (t->parent ||
            (d->options.transaction_filter &&
             (!requested || !descends_from(d, requested, t->xid))))
            continue;
        bson_t *event = new_event(d, t->xid, 0, "transaction", NULL,
                                 "incomplete", "transaction outcome is absent at end of supplied WAL");
        if (!event)
            return error_message(error, size, "out of memory reporting unresolved transaction");
        BSON_APPEND_UTF8(event, "outcome", "unresolved");
        bool ok = output_event(&d->options, event);
        bson_destroy(event);
        if (!ok)
            return error_message(error, size, "unresolved transaction output failed");
    }

    if (fflush(stdout) || ferror(stdout))
        return error_message(error, size, "output flush failed");
    while (d->transactions)
    {
        Transaction *t = d->transactions;
        d->transactions = t->next;
        if (!free_transaction(d, t))
            return error_message(error, size, "cannot remove transaction spill file");
    }
    if (unresolved)
        return error_message(error, size, "incomplete WAL: unresolved transaction outcomes");
    if (d->options.strict && d->incomplete)
        return error_message(error, size, "strict decoding failed: incomplete document reconstruction");
    if (d->catalog && d->options.rebuild_cache &&
        !audit_catalog_cache_publish_rebuild(d->catalog, error, size))
        return false;
    return true;
}

bool
audit_decoder_mark_gap(AuditDecoder *d, XLogRecPtr gap_lsn,
                       char *error, size_t size)
{
    if (!d)
        return error_message(error, size, "decoder is unavailable");
    if (d->page_state &&
        !audit_page_state_mark_gap(d->page_state, gap_lsn, error, size))
        return false;
    if (d->catalog &&
        !audit_catalog_cache_mark_gap(d->catalog, gap_lsn, error, size))
        return false;
    return true;
}

void
audit_decoder_destroy(AuditDecoder *d)
{
    if (!d)
        return;
    while (d->transactions)
    {
        Transaction *t = d->transactions;
        d->transactions = t->next;
        if (!free_transaction(d, t))
            fprintf(stderr, "documentdb-wal-audit: cannot remove private transaction spill file\n");
    }
    audit_page_state_destroy(d->page_state);
    audit_catalog_cache_close(d->catalog);
    if (d->ephemeral_catalog_path)
    {
        char error[256];
        if (!audit_catalog_cache_delete(d->ephemeral_catalog_path,
                                        error, sizeof(error)))
            fprintf(stderr, "documentdb-wal-audit: %s\n", error);
    }
    free(d->ephemeral_catalog_path);
    audit_manifest_free(&d->manifest);
    free(d);
}

bool
audit_write_error(const AuditOptions *options, const char *message, XLogRecPtr lsn)
{
    bson_t event;
    bool ok;
    bson_init(&event);
    BSON_APPEND_INT32(&event, "schemaVersion", 1);
    BSON_APPEND_UTF8(&event, "eventType", "error");
    BSON_APPEND_UTF8(&event, "certainty", "incomplete");
    BSON_APPEND_UTF8(&event, "message", message);
    append_lsn(&event, "eventLsn", lsn);
    BSON_APPEND_INT64(&event, "transactionId", 0);
    ok = output_event(options, &event) && !fflush(stdout);
    bson_destroy(&event);
    if (fprintf(stderr, "documentdb-wal-audit: %s\n", message) < 0)
        ok = false;
    return ok;
}
