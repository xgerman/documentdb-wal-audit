#include "postgres.h"
#include "audit_private.h"
#include "access/heapam_xlog.h"
#include "access/htup_details.h"
#include "varatt.h"
#include <stdio.h>
#include <string.h>

static bool
tuple_error(char *error, size_t size, const char *message)
{
    snprintf(error, size, "%s", message);
    return false;
}

static bool
get_bson(const uint8 *data, size_t length, size_t *offset, uint64 limit,
         bson_t *value, char *error, size_t size)
{
    size_t pos = *offset, header, bytes;
    uint32 word;
    const uint8 *payload;
    if (pos >= length)
        return tuple_error(error, size, "missing BSON attribute");
    /* att_align_pointer permits short varlena values without alignment. */
    if (data[pos] == 0)
        pos = ((pos + SizeofHeapTupleHeader + 3) & ~(size_t)3) - SizeofHeapTupleHeader;
    if (pos >= length)
        return tuple_error(error, size, "truncated varlena alignment");
    if (VARATT_IS_1B_E(data + pos))
        return tuple_error(error, size, "external TOAST value is unavailable");
    if (VARATT_IS_1B(data + pos))
    {
        header = VARHDRSZ_SHORT;
        bytes = VARSIZE_1B(data + pos);
    }
    else
    {
        if (length - pos < 4)
            return tuple_error(error, size, "truncated varlena header");
        memcpy(&word, data + pos, sizeof(word));
        if (VARATT_IS_4B_C(data + pos))
            return tuple_error(error, size, "compressed BSON is unsupported");
        header = VARHDRSZ;
#ifdef WORDS_BIGENDIAN
        bytes = word & 0x3fffffff;
#else
        bytes = word >> 2;
#endif
    }
    if (bytes < header + 5 || bytes > length - pos || bytes - header > limit)
        return tuple_error(error, size, "invalid or oversized BSON attribute");
    payload = data + pos + header;
    if (!bson_init_static(value, payload, (uint32)(bytes - header)) ||
        !bson_validate(value, BSON_VALIDATE_UTF8 | BSON_VALIDATE_UTF8_ALLOW_NULL, NULL))
        return tuple_error(error, size, "invalid BSON payload");
    *offset = pos + bytes;
    return true;
}

static bool
read_tuple_header(const uint8 **data, size_t *length, size_t *offset,
                  unsigned *natts, unsigned *nonnull, char *error, size_t size)
{
    xl_heap_header header;
    if (*length < SizeOfHeapHeader)
        return tuple_error(error, size, "missing heap tuple header");
    memset(&header, 0, sizeof(header));
    memcpy(&header, *data, SizeOfHeapHeader);
    *natts = header.t_infomask2 & HEAP_NATTS_MASK;
    if (*natts != 3 && *natts != 4)
        return tuple_error(error, size, "unknown DocumentDB tuple schema");
    if (header.t_hoff != MAXALIGN(SizeofHeapTupleHeader +
                     ((header.t_infomask & HEAP_HASNULL) ? BITMAPLEN(*natts) : 0)))
        return tuple_error(error, size, "invalid tuple data offset");
    *data += SizeOfHeapHeader;
    *length -= SizeOfHeapHeader;
    *offset = header.t_hoff - SizeofHeapTupleHeader;
    if (*offset > *length)
        return tuple_error(error, size, "truncated tuple bitmap or padding");
    *nonnull = (header.t_infomask & HEAP_HASNULL) ?
               (*data)[0] : (1U << *natts) - 1;
    return true;
}

static bool
skip_shard_key(size_t length, size_t *offset, unsigned nonnull,
               char *error, size_t size)
{
    if (nonnull & 1)
    {
        if (*offset > length || length - *offset < 8)
            return tuple_error(error, size, "missing shard key");
        *offset += 8;
    }
    return true;
}

static bool
finish_tuple(size_t length, size_t offset, unsigned natts, unsigned nonnull,
             char *error, size_t size)
{
    if (natts == 4 && (nonnull & 8))
    {
        offset = ((offset + SizeofHeapTupleHeader + 7) & ~(size_t)7) - SizeofHeapTupleHeader;
        if (offset > length || length - offset < 8)
            return tuple_error(error, size, "truncated timestamp attribute");
        offset += 8;
    }
    if (offset != length)
        return tuple_error(error, size, "unexpected tuple trailing bytes");
    return true;
}

static bool
check_object_id(const bson_t *object_id, bson_iter_t *id, char *error, size_t size)
{
    if (bson_count_keys(object_id) != 1 ||
        !bson_iter_init_find(id, object_id, ""))
        return tuple_error(error, size, "object_id must contain exactly one empty-key value");
    return true;
}

bool
audit_tuple_decode(const uint8 *data, size_t length, uint64 limit,
                   bson_t *object_id, bson_t *document, char *error, size_t size)
{
    size_t offset;
    unsigned natts, nonnull;
    bson_iter_t id, docid;
    bson_t left, right;
    bool matches;
    if (!read_tuple_header(&data, &length, &offset, &natts, &nonnull, error, size))
        return false;
    if ((nonnull & 7) != 7)
        return tuple_error(error, size, "required DocumentDB attribute is NULL");
    if (!skip_shard_key(length, &offset, nonnull, error, size) ||
        !get_bson(data, length, &offset, limit, object_id, error, size) ||
        !get_bson(data, length, &offset, limit, document, error, size) ||
        !finish_tuple(length, offset, natts, nonnull, error, size) ||
        !check_object_id(object_id, &id, error, size))
        return false;
    if (!bson_iter_init_find(&docid, document, "_id"))
        return tuple_error(error, size, "document must contain _id matching object_id");
    bson_init(&left);
    bson_init(&right);
    bson_append_value(&left, "_id", 3, bson_iter_value(&id));
    bson_append_value(&right, "_id", 3, bson_iter_value(&docid));
    matches = bson_equal(&left, &right);
    bson_destroy(&left);
    bson_destroy(&right);
    if (!matches)
        return tuple_error(error, size, "object_id does not match document _id");
    return true;
}

bool
audit_tuple_key_decode(const uint8 *data, size_t length, uint64 limit,
                       bson_t *object_id, char *error, size_t size)
{
    size_t offset;
    unsigned natts, nonnull;
    bson_iter_t id;
    if (!read_tuple_header(&data, &length, &offset, &natts, &nonnull, error, size))
        return false;
    if (!(nonnull & 2) || (nonnull & 4))
        return tuple_error(error, size, "unsupported replica-identity key tuple");
    return skip_shard_key(length, &offset, nonnull, error, size) &&
           get_bson(data, length, &offset, limit, object_id, error, size) &&
           finish_tuple(length, offset, natts, nonnull, error, size) &&
           check_object_id(object_id, &id, error, size);
}
