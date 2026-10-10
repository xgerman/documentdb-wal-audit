#include "postgres_fe.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <unistd.h>

#include "access/xlog_internal.h"
#include "wal_reader.h"

typedef struct WalInput
{
    char *path;
    XLogSegNo number;
    TimeLineID timeline;
    uint32 log;
    uint32 segment;
} WalInput;

typedef struct WalContext
{
    WalInput *inputs;
    size_t count;
    int segment_size;
    uint64 system_identifier;
    TimeLineID timeline;
    uint64 max_record_bytes;
    int fd;
    size_t open_index;
    char error[1024];
} WalContext;

static bool
fail(WalContext *ctx, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsnprintf(ctx->error, sizeof(ctx->error), format, ap);
    va_end(ap);
    return false;
}

static bool
read_exact(WalContext *ctx, int fd, void *buffer, size_t length, off_t offset)
{
    char *p = buffer;
    while (length)
    {
        ssize_t got = pread(fd, p, length, offset);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return fail(ctx, "WAL read failed at offset %lld: %s",
                        (long long) offset, got < 0 ? strerror(errno) : "truncated file");
        p += got;
        offset += got;
        length -= got;
    }
    return true;
}

static bool
wal_filename(const char *path, WalInput *input)
{
    const char *name = strrchr(path, '/');
    uint32 parts[3] = {0, 0, 0};
    name = name ? name + 1 : path;
    if (strlen(name) != 24)
        return false;
    for (int i = 0; i < 24; ++i)
    {
        unsigned digit;
        if (name[i] >= '0' && name[i] <= '9') digit = name[i] - '0';
        else if (name[i] >= 'A' && name[i] <= 'F') digit = name[i] - 'A' + 10;
        else return false;
        parts[i / 8] = (parts[i / 8] << 4) | digit;
    }
    input->timeline = parts[0];
    input->log = parts[1];
    input->segment = parts[2];
    return input->timeline != 0;
}

static bool
add_input(WalContext *ctx, const char *path)
{
    WalInput input = {0};
    WalInput *new_inputs;
    if (!wal_filename(path, &input))
        return fail(ctx, "Invalid WAL segment filename: %s (expected 24 uppercase hex digits)", path);
    if (ctx->count >= SIZE_MAX / sizeof(WalInput) - 1)
        return fail(ctx, "Too many WAL files");
    new_inputs = realloc(ctx->inputs, (ctx->count + 1) * sizeof(WalInput));
    if (!new_inputs)
        return fail(ctx, "Out of memory collecting WAL files");
    ctx->inputs = new_inputs;
    input.path = strdup(path);
    if (!input.path)
        return fail(ctx, "Out of memory collecting WAL filenames");
    ctx->inputs[ctx->count++] = input;
    return true;
}

static int
compare_inputs(const void *a, const void *b)
{
    const WalInput *left = a, *right = b;
    if (left->timeline != right->timeline)
        return left->timeline < right->timeline ? -1 : 1;
    if (left->log != right->log)
        return left->log < right->log ? -1 : 1;
    return left->segment < right->segment ? -1 : left->segment != right->segment;
}

static bool
collect_inputs(WalContext *ctx, const char *directory, int count, char **paths)
{
    if (directory)
    {
        DIR *dir = opendir(directory);
        struct dirent *entry;
        bool ok = true;
        if (!dir)
            return fail(ctx, "Cannot open WAL directory %s: %s", directory, strerror(errno));
        errno = 0;
        while ((entry = readdir(dir)) != NULL)
        {
            char *path;
            size_t length;
            /* PostgreSQL archives also contain history and backup files. */
            if (strlen(entry->d_name) != 24)
                continue;
            length = strlen(directory) + strlen(entry->d_name) + 2;
            path = malloc(length);
            if (!path)
            {
                ok = fail(ctx, "Out of memory collecting WAL directory");
                break;
            }
            snprintf(path, length, "%s/%s", directory, entry->d_name);
            ok = add_input(ctx, path);
            free(path);
            if (!ok)
                break;
            errno = 0;
        }
        if (ok && errno)
            ok = fail(ctx, "Cannot enumerate WAL directory: %s", strerror(errno));
        closedir(dir);
        if (!ok) return false;
    }
    else
        for (int i = 0; i < count; ++i)
            if (!add_input(ctx, paths[i])) return false;
    if (!ctx->count)
        return fail(ctx, "No WAL segments supplied");
    qsort(ctx->inputs, ctx->count, sizeof(WalInput), compare_inputs);
    return true;
}

static bool
validate_inputs(WalContext *ctx)
{
    for (size_t i = 0; i < ctx->count; ++i)
    {
        WalInput *input = &ctx->inputs[i];
        XLogLongPageHeaderData header;
        struct stat st;
        int fd = open(input->path, O_RDONLY | O_CLOEXEC);
        bool ok;
        if (fd < 0)
            return fail(ctx, "Cannot open WAL file %s: %s", input->path, strerror(errno));
        ok = fstat(fd, &st) == 0;
        if (!ok)
            fail(ctx, "Cannot stat WAL file %s: %s", input->path, strerror(errno));
        else if (!S_ISREG(st.st_mode))
            ok = fail(ctx, "WAL input is not a regular file: %s", input->path);
        else
            ok = read_exact(ctx, fd, &header, sizeof(header), 0);
        close(fd);
        if (!ok) return false;
        if (header.std.xlp_magic != XLOG_PAGE_MAGIC)
            return fail(ctx, "WAL magic mismatch in %s: requires PostgreSQL %d",
                        input->path, PG_VERSION_NUM / 10000);
        if (!(header.std.xlp_info & XLP_LONG_HEADER) ||
            (header.std.xlp_info & ~XLP_ALL_FLAGS))
            return fail(ctx, "Invalid WAL long page header in %s", input->path);
        if (!IsValidWalSegSize(header.xlp_seg_size) ||
            header.xlp_xlog_blcksz != XLOG_BLCKSZ ||
            st.st_size != header.xlp_seg_size)
            return fail(ctx, "Invalid WAL segment size, block size, or exact file length in %s",
                        input->path);
        if (!header.xlp_sysid || header.std.xlp_tli != input->timeline ||
            input->segment >= XLogSegmentsPerXLogId(header.xlp_seg_size))
            return fail(ctx, "WAL filename/header identity mismatch in %s", input->path);
        input->number = (uint64) input->log * XLogSegmentsPerXLogId(header.xlp_seg_size)
            + input->segment;
        if (input->number >= UINT64_MAX / header.xlp_seg_size ||
            header.std.xlp_pageaddr != input->number * header.xlp_seg_size)
            return fail(ctx, "WAL filename/page address mismatch in %s", input->path);
        if (i == 0)
        {
            ctx->segment_size = header.xlp_seg_size;
            ctx->system_identifier = header.xlp_sysid;
            ctx->timeline = input->timeline;
        }
        else
        {
            if (header.xlp_seg_size != (uint32) ctx->segment_size ||
                header.xlp_sysid != ctx->system_identifier || input->timeline != ctx->timeline)
                return fail(ctx, "Mixed WAL cluster, timeline, or segment size in %s", input->path);
            if (input->number == ctx->inputs[i - 1].number)
                return fail(ctx, "Duplicate WAL segment: %s", input->path);
            if (input->number != ctx->inputs[i - 1].number + 1)
                return fail(ctx, "Missing WAL segment before %s", input->path);
        }
    }
    return true;
}

static bool
open_page(WalContext *ctx, XLogRecPtr page, size_t *index)
{
    XLogSegNo number = page / ctx->segment_size;
    XLogSegNo first = ctx->inputs[0].number;
    if (number < first || number - first >= ctx->count)
        return fail(ctx, "Missing WAL segment at %X/%X", LSN_FORMAT_ARGS(page));
    *index = (size_t) (number - first);
    if (ctx->fd < 0 || ctx->open_index != *index)
    {
        if (ctx->fd >= 0) close(ctx->fd);
        ctx->fd = open(ctx->inputs[*index].path, O_RDONLY | O_CLOEXEC);
        if (ctx->fd < 0)
            return fail(ctx, "Cannot reopen WAL segment: %s", strerror(errno));
        ctx->open_index = *index;
    }
    return true;
}

static bool
read_page(WalContext *ctx, XLogRecPtr page, char *buffer)
{
    size_t index;
    if (!open_page(ctx, page, &index)) return false;
    return read_exact(ctx, ctx->fd, buffer, XLOG_BLCKSZ,
                      page % ctx->segment_size);
}

static bool
validate_page(WalContext *ctx, XLogRecPtr page, const char *buffer)
{
    XLogPageHeader header = (XLogPageHeader) buffer;
    bool long_header = page % ctx->segment_size == 0;
    if (header->xlp_magic != XLOG_PAGE_MAGIC ||
        header->xlp_tli != ctx->timeline || header->xlp_pageaddr != page ||
        (header->xlp_info & ~XLP_ALL_FLAGS) ||
        !!(header->xlp_info & XLP_LONG_HEADER) != long_header)
        return fail(ctx, "Invalid WAL page header at %X/%X", LSN_FORMAT_ARGS(page));
    if (long_header)
    {
        XLogLongPageHeader long_page = (XLogLongPageHeader) buffer;
        if (long_page->xlp_sysid != ctx->system_identifier ||
            long_page->xlp_seg_size != (uint32) ctx->segment_size ||
            long_page->xlp_xlog_blcksz != XLOG_BLCKSZ)
            return fail(ctx, "WAL long header identity mismatch at %X/%X",
                        LSN_FORMAT_ARGS(page));
    }
    if (header->xlp_rem_len > ctx->max_record_bytes)
        return fail(ctx, "WAL continuation exceeds --max-record-bytes at %X/%X",
                    LSN_FORMAT_ARGS(page));
    if ((header->xlp_info & XLP_FIRST_IS_CONTRECORD) ?
        header->xlp_rem_len == 0 : header->xlp_rem_len != 0)
        return fail(ctx, "Invalid WAL continuation length at %X/%X",
                    LSN_FORMAT_ARGS(page));
    /* An overwritten continuation is not a complete offline history. */
    if (header->xlp_info & XLP_FIRST_IS_OVERWRITE_CONTRECORD)
        return fail(ctx, "Overwritten/missing WAL continuation at %X/%X",
                    LSN_FORMAT_ARGS(page));
    return true;
}

static int
page_read_callback(XLogReaderState *reader, XLogRecPtr page, int requested,
                   XLogRecPtr record, char *buffer)
{
    WalContext *ctx = reader->private_data;
    if (!read_page(ctx, page, buffer) || !validate_page(ctx, page, buffer))
        return -1;
    reader->seg.ws_tli = ctx->timeline;
    /* XLogReader owns CRC, record layout, and continuation assembly. */
    return XLOG_BLCKSZ;
}

static void
segment_close_callback(XLogReaderState *reader)
{
    if (reader->seg.ws_file >= 0)
        close(reader->seg.ws_file);
    reader->seg.ws_file = -1;
}

static bool
zero_bytes(const char *buffer, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        if (buffer[i] != 0) return false;
    return true;
}

/* Zero padding is legal only after the last complete record in the last input. */
static bool
validate_tail(WalContext *ctx, XLogRecPtr position)
{
    size_t index;
    char buffer[XLOG_BLCKSZ];
    off_t offset = position % ctx->segment_size;
    if (!open_page(ctx, position, &index)) return false;
    if (index != ctx->count - 1)
        return fail(ctx, "Unexpected zero WAL tail before final segment at %X/%X",
                    LSN_FORMAT_ARGS(position));
    while (offset < ctx->segment_size)
    {
        size_t length = Min(sizeof(buffer), (size_t) (ctx->segment_size - offset));
        if (!read_exact(ctx, ctx->fd, buffer, length, offset)) return false;
        if (!zero_bytes(buffer, length))
            return fail(ctx, "Nonzero WAL after zero tail at %X/%X",
                        LSN_FORMAT_ARGS(position));
        offset += length;
    }
    return true;
}

/*
 * Check the first length word before handing a record to XLogReader. This is
 * needed even on cached pages, where its page callback is not called again.
 */
static int
preflight_record(WalContext *ctx, XLogRecPtr position, XLogRecPtr end,
                 XLogRecPtr *actual)
{
    union { uint64 alignment; char bytes[XLOG_BLCKSZ]; } page_buffer;
    char *buffer = page_buffer.bytes;
    XLogRecPtr page = position - position % XLOG_BLCKSZ;
    size_t offset = position % XLOG_BLCKSZ;
    uint32 length;
    XLogPageHeader header;

    if (position == end) return 0;
    if (position > end)
        return fail(ctx, "Record extends beyond supplied WAL"), -1;
    if (!read_page(ctx, page, buffer)) return -1;
    if (zero_bytes(buffer, XLOG_BLCKSZ))
        return validate_tail(ctx, position) ? 0 : -1;
    if (!validate_page(ctx, page, buffer)) return -1;
    header = (XLogPageHeader) buffer;
    if (!offset) offset = XLogPageHeaderSize(header);
    if (offset < XLogPageHeaderSize(header) || offset > XLOG_BLCKSZ - sizeof(length))
        return fail(ctx, "Invalid WAL record offset at %X/%X",
                    LSN_FORMAT_ARGS(position)), -1;
    *actual = page + offset;
    memcpy(&length, buffer + offset, sizeof(length));
    if (!length)
        return validate_tail(ctx, *actual) ? 0 : -1;
    if (length < SizeOfXLogRecord)
        return fail(ctx, "Invalid WAL record length %u at %X/%X",
                    length, LSN_FORMAT_ARGS(*actual)), -1;
    if (length > ctx->max_record_bytes)
        return fail(ctx, "WAL record length %u exceeds --max-record-bytes at %X/%X",
                    length, LSN_FORMAT_ARGS(*actual)), -1;
    return 1;
}

static bool
initial_position(WalContext *ctx, XLogRecPtr *position)
{
    union { uint64 alignment; char bytes[XLOG_BLCKSZ]; } buffer;
    uint32 expected_remaining = 0;
    bool skipping = false;
    *position = ctx->inputs[0].number * ctx->segment_size;
    for (;;)
    {
        XLogPageHeader header;
        size_t header_size;
        if (!read_page(ctx, *position, buffer.bytes) ||
            !validate_page(ctx, *position, buffer.bytes)) return false;
        header = (XLogPageHeader) buffer.bytes;
        header_size = XLogPageHeaderSize(header);
        if (!(header->xlp_info & XLP_FIRST_IS_CONTRECORD))
        {
            if (skipping)
                return fail(ctx, "Missing initial WAL continuation");
            *position += header_size;
            return true;
        }
        if (expected_remaining && header->xlp_rem_len != expected_remaining)
            return fail(ctx, "Inconsistent initial WAL continuation");
        if (!skipping)
            fprintf(stderr, "warning: input starts with a WAL continuation; preceding record is unavailable\n");
        skipping = true;
        if (header->xlp_rem_len < XLOG_BLCKSZ - header_size)
        {
            *position += header_size + MAXALIGN((uint64) header->xlp_rem_len);
            return true;
        }
        expected_remaining = header->xlp_rem_len - (XLOG_BLCKSZ - header_size);
        *position += XLOG_BLCKSZ;
        if (!expected_remaining)
            return true;
    }
}

int
audit_read_wal(AuditOptions *options, const char *wal_dir, int path_count, char **paths)
{
    WalContext ctx = {0};
    XLogReaderState *reader = NULL;
    AuditDecoder *decoder = NULL;
    XLogRecPtr position = InvalidXLogRecPtr, end;
    int result = 1;
    XLogReaderRoutine routine = {0};
    ctx.fd = -1;
    ctx.max_record_bytes = options->max_record_bytes;
    if (!collect_inputs(&ctx, wal_dir, path_count, paths) || !validate_inputs(&ctx))
        goto error;
    options->system_identifier = ctx.system_identifier;
    options->timeline = ctx.timeline;
    options->wal_segment_size = ctx.segment_size;
    end = (ctx.inputs[ctx.count - 1].number + 1) * ctx.segment_size;
    if (!end || options->from_lsn >= end)
    {
        fail(&ctx, "Requested start LSN is beyond supplied WAL");
        goto error;
    }
    if (!initial_position(&ctx, &position)) goto error;
    routine.page_read = page_read_callback;
    routine.segment_close = segment_close_callback;
    reader = XLogReaderAllocate(ctx.segment_size, NULL, &routine, &ctx);
    if (!reader)
    {
        fail(&ctx, "Cannot allocate PostgreSQL XLogReader");
        goto error;
    }
    reader->system_identifier = ctx.system_identifier;
    decoder = audit_decoder_create(options, ctx.error, sizeof(ctx.error));
    if (!decoder) goto error;
    XLogBeginRead(reader, position);
    while (reader->NextRecPtr < options->to_lsn)
    {
        char *native_error = NULL;
        XLogRecord *record;
        int status = preflight_record(&ctx, reader->NextRecPtr, end, &position);
        if (status < 0)
        {
            if (decoder)
                audit_decoder_mark_gap(decoder, position,
                                       ctx.error, sizeof(ctx.error));
            goto error;
        }
        if (!status || position >= options->to_lsn) break;
        record = XLogReadRecord(reader, &native_error);
        if (!record)
        {
            if (!ctx.error[0])
                fail(&ctx, "%s", native_error ? native_error : "Incomplete/corrupt WAL record");
            audit_decoder_mark_gap(decoder, reader->NextRecPtr,
                                   ctx.error, sizeof(ctx.error));
            goto error;
        }
        position = reader->ReadRecPtr;
        if (reader->overwrittenRecPtr != InvalidXLogRecPtr)
        {
            fail(&ctx, "Missing/overwritten WAL record");
            audit_decoder_mark_gap(decoder, reader->overwrittenRecPtr,
                                   ctx.error, sizeof(ctx.error));
            goto error;
        }
        if (!audit_decoder_process(decoder, reader, ctx.error, sizeof(ctx.error)))
            goto error;
    }
    if (!audit_decoder_finish(decoder, ctx.error, sizeof(ctx.error))) goto error;
    if (fflush(stdout) != 0)
    {
        fail(&ctx, "Cannot flush output: %s", strerror(errno));
        goto error;
    }
    result = 0;
    goto cleanup;

error:
    if (!ctx.error[0]) fail(&ctx, "WAL audit failed");
    audit_write_error(options, ctx.error, position);
    fprintf(stderr, "error: %s\n", ctx.error);
cleanup:
    if (decoder) audit_decoder_destroy(decoder);
    if (reader) XLogReaderFree(reader);
    if (ctx.fd >= 0) close(ctx.fd);
    for (size_t i = 0; i < ctx.count; ++i) free(ctx.inputs[i].path);
    free(ctx.inputs);
    return result;
}
