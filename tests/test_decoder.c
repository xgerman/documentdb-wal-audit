#include "postgres.h"
#include "audit_private.h"
#include "access/heapam_xlog.h"
#include "access/htup_details.h"
#include "varatt.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t
append_value(uint8 *tuple, size_t position, const bson_t *value, bool short_header)
{
    size_t length = value->len + (short_header ? VARHDRSZ_SHORT : VARHDRSZ);
    uint32 word;
    if (short_header)
        SET_VARSIZE_SHORT(tuple + SizeOfHeapHeader + position, length);
    else
    {
        position = ((position + SizeofHeapTupleHeader + 3) & ~(size_t)3) - SizeofHeapTupleHeader;
#ifdef WORDS_BIGENDIAN
        word = length;
#else
        word = length << 2;
#endif
        memcpy(tuple + SizeOfHeapHeader + position, &word, sizeof(word));
    }
    memcpy(tuple + SizeOfHeapHeader + position + (short_header ? 1 : 4),
           bson_get_data(value), value->len);
    return position + length;
}

static size_t
make_tuple(uint8 *tuple, bool short_header, bool timestamp, bool nullable,
           bool mismatch)
{
    xl_heap_header header = {0};
    bson_t id, document;
    size_t position = 9;
    memset(tuple, 0, 512);
    header.t_infomask2 = timestamp ? 4 : 3;
    header.t_infomask = nullable ? HEAP_HASNULL : 0;
    header.t_hoff = 24;
    memcpy(tuple, &header, SizeOfHeapHeader);
    if (nullable)
        tuple[SizeOfHeapHeader] = 7;
    bson_init(&id);
    bson_init(&document);
    BSON_APPEND_INT32(&id, "", 42);
    BSON_APPEND_INT32(&document, "_id", mismatch ? 43 : 42);
    BSON_APPEND_INT32(&document, "value", 7);
    position = append_value(tuple, position, &id, short_header);
    position = append_value(tuple, position, &document, short_header);
    bson_destroy(&id);
    bson_destroy(&document);
    if (timestamp && !nullable)
        position = ((position + SizeofHeapTupleHeader + 7) & ~(size_t)7) - SizeofHeapTupleHeader + 8;
    return position + SizeOfHeapHeader;
}

static size_t
make_key_tuple(uint8 *tuple, bool short_header, bool shard_key, bool timestamp_column)
{
    xl_heap_header header = {0};
    bson_t id;
    size_t position = shard_key ? 9 : 1;
    memset(tuple, 0, 512);
    header.t_infomask2 = timestamp_column ? 4 : 3;
    header.t_infomask = HEAP_HASNULL;
    header.t_hoff = 24;
    memcpy(tuple, &header, SizeOfHeapHeader);
    tuple[SizeOfHeapHeader] = shard_key ? 3 : 2;
    bson_init(&id);
    BSON_APPEND_INT32(&id, "", 42);
    position = append_value(tuple, position, &id, short_header);
    bson_destroy(&id);
    return position + SizeOfHeapHeader;
}

int
main(void)
{
    uint8 tuple[512];
    bson_t id, document;
    char error[256];
    size_t length;
    for (unsigned flags = 0; flags < 8; flags++)
    {
        length = make_tuple(tuple, flags & 1, flags & 2, flags & 4, false);
        assert(audit_tuple_decode(tuple, length, 1024, &id, &document, error, sizeof(error)));
        char *canonical = bson_as_canonical_extended_json(&document, NULL);
        assert(canonical && strstr(canonical, "$numberInt"));
        bson_free(canonical);
        for (size_t truncated = 0; truncated < length; truncated++)
            assert(!audit_tuple_decode(tuple, truncated, 1024, &id, &document, error, sizeof(error)));
        assert(!audit_tuple_decode(tuple, length, 5, &id, &document, error, sizeof(error)));
    }
    length = make_tuple(tuple, false, false, false, true);
    assert(!audit_tuple_decode(tuple, length, 1024, &id, &document, error, sizeof(error)));
    length = make_tuple(tuple, false, false, true, false);
    tuple[SizeOfHeapHeader] = 5;
    assert(!audit_tuple_decode(tuple, length, 1024, &id, &document, error, sizeof(error)));
    length = make_tuple(tuple, false, false, false, false);
    tuple[4] = 32;
    assert(!audit_tuple_decode(tuple, length, 1024, &id, &document, error, sizeof(error)));
    length = make_tuple(tuple, true, false, false, false);
#ifdef WORDS_BIGENDIAN
    tuple[SizeOfHeapHeader + 9] = 0x80;
#else
    tuple[SizeOfHeapHeader + 9] = 1;
#endif
    assert(!audit_tuple_decode(tuple, length, 1024, &id, &document, error, sizeof(error)));
    for (unsigned flags = 0; flags < 8; flags++)
    {
        length = make_key_tuple(tuple, flags & 1, flags & 2, flags & 4);
        assert(!audit_tuple_decode(tuple, length, 1024, &id, &document, error, sizeof(error)));
        assert(audit_tuple_key_decode(tuple, length, 1024, &id, error, sizeof(error)));
        bson_iter_t value;
        assert(bson_iter_init_find(&value, &id, "") && bson_iter_int32(&value) == 42);
        for (size_t truncated = 0; truncated < length; truncated++)
            assert(!audit_tuple_key_decode(tuple, truncated, 1024, &id, error, sizeof(error)));
        assert(!audit_tuple_key_decode(tuple, length, 5, &id, error, sizeof(error)));
        tuple[SizeOfHeapHeader] = 1;
        assert(!audit_tuple_key_decode(tuple, length, 1024, &id, error, sizeof(error)));
    }
    length = make_tuple(tuple, false, false, false, false);
    assert(!audit_tuple_key_decode(tuple, length, 1024, &id, error, sizeof(error)));
    bson_t invalid;
    bson_init(&invalid);
    for (unsigned shape = 0; shape < 3; shape++)
    {
        bson_reinit(&invalid);
        if (shape == 0)
            BSON_APPEND_INT32(&invalid, "_id", 42);
        else if (shape == 1)
        {
            BSON_APPEND_INT32(&invalid, "", 42);
            BSON_APPEND_INT32(&invalid, "", 43);
        }
        make_key_tuple(tuple, false, true, false);
        length = append_value(tuple, 9, &invalid, false) + SizeOfHeapHeader;
        assert(!audit_tuple_key_decode(tuple, length, 1024, &id, error, sizeof(error)));
        assert(strstr(error, "exactly one empty-key value"));
        make_tuple(tuple, false, false, false, false);
        size_t position = append_value(tuple, 9, &invalid, false);
        bson_t document_value;
        bson_init(&document_value);
        BSON_APPEND_INT32(&document_value, "_id", 42);
        length = append_value(tuple, position, &document_value, false) + SizeOfHeapHeader;
        assert(!audit_tuple_decode(tuple, length, 1024, &id, &document, error, sizeof(error)));
        assert(strstr(error, "exactly one empty-key value"));
        bson_destroy(&document_value);
    }
    bson_destroy(&invalid);
    puts("ordinary BSON tuple decoder tests passed");
    return 0;
}
