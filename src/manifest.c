#include "audit_private.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool
fail(char *error, size_t size, const char *message)
{
    snprintf(error, size, "manifest: %s", message);
    return false;
}

static bool
plain_json_structure(const char *json, size_t length)
{
    char stack[3];
    unsigned depth = 0;
    bool quoted = false;
    for (size_t i = 0; i < length; i++)
    {
        char c = json[i];
        if (quoted)
        {
            if (c == '\\')
                i++;
            else if (c == '"')
                quoted = false;
            continue;
        }
        if (c == '"')
            quoted = true;
        else if (c == '{' || c == '[')
        {
            /* Only root object, relations array, and relation objects exist.
             * In particular, Extended JSON wrappers are not integer types. */
            if (!((depth == 0 && c == '{') ||
                  (depth == 1 && c == '[' && stack[0] == '{') ||
                  (depth == 2 && c == '{' && stack[1] == '[')))
                return false;
            stack[depth++] = c;
        }
        else if (c == '}' || c == ']')
        {
            if (!depth || stack[depth - 1] != (c == '}' ? '{' : '['))
                return false;
            depth--;
        }
    }
    return !quoted && depth == 0;
}

static bool
keys_valid(const bson_t *doc, const char *allowed, unsigned depth)
{
    bson_iter_t it, previous;
    if (depth > 16 || !bson_iter_init(&it, doc))
        return false;
    while (bson_iter_next(&it))
    {
        const char *key = bson_iter_key(&it);
        char token[128];
        snprintf(token, sizeof(token), "|%s|", key);
        if (allowed && (!strstr(allowed, token) || strlen(key) > 100))
            return false;
        bson_iter_init(&previous, doc);
        while (bson_iter_next(&previous) && previous.off < it.off)
            if (strcmp(bson_iter_key(&previous), key) == 0)
                return false;
        if (BSON_ITER_HOLDS_DOCUMENT(&it) || BSON_ITER_HOLDS_ARRAY(&it))
        {
            const uint8_t *bytes;
            uint32_t length;
            bson_t nested;
            if (BSON_ITER_HOLDS_DOCUMENT(&it))
                bson_iter_document(&it, &length, &bytes);
            else
                bson_iter_array(&it, &length, &bytes);
            if (!bson_init_static(&nested, bytes, length) ||
                !keys_valid(&nested, NULL, depth + 1))
                return false;
        }
    }
    return true;
}

static bool
integer(const bson_t *doc, const char *key, uint64 max, uint64 *result)
{
    bson_iter_t it;
    int64_t value;
    if (!bson_iter_init_find(&it, doc, key) ||
        !(BSON_ITER_HOLDS_INT32(&it) || BSON_ITER_HOLDS_INT64(&it)))
        return false;
    value = bson_iter_as_int64(&it);
    if (value < 0 || (uint64)value > max)
        return false;
    *result = (uint64)value;
    return true;
}

static const char *
string_value(const bson_t *doc, const char *key)
{
    bson_iter_t it;
    uint32_t length;
    const char *value;
    if (!bson_iter_init_find(&it, doc, key) || !BSON_ITER_HOLDS_UTF8(&it))
        return NULL;
    value = bson_iter_utf8(&it, &length);
    return length && strlen(value) == length ? value : NULL;
}

static bool
parse_lsn(const char *value, XLogRecPtr *lsn)
{
    unsigned long hi, lo;
    char *end;
    const char *p;
    if (!value || !(p = strchr(value, '/')) || p == value || !p[1])
        return false;
    for (const char *q = value; *q; q++)
        if (*q != '/' && !((*q >= '0' && *q <= '9') ||
            (*q >= 'a' && *q <= 'f') || (*q >= 'A' && *q <= 'F')))
            return false;
    errno = 0;
    hi = strtoul(value, &end, 16);
    if (errno || end != p || hi > UINT32_MAX)
        return false;
    lo = strtoul(p + 1, &end, 16);
    if (errno || *end || lo > UINT32_MAX)
        return false;
    *lsn = ((uint64)hi << 32) | lo;
    return true;
}

bool
audit_manifest_load(const char *path, AuditManifest *m, char *error, size_t size)
{
    FILE *file = NULL;
    char *json = NULL;
    bson_t *doc = NULL;
    bson_error_t bson_error;
    bson_iter_t it, entries;
    uint64 value;
    long length;
    bool ok = false;
    const char *system, *version;
    unsigned schema_version;
    memset(m, 0, sizeof(*m));
    file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END) || (length = ftell(file)) < 0 ||
        length > 16 * 1024 * 1024 || fseek(file, 0, SEEK_SET))
        goto invalid;
    json = malloc((size_t)length + 1);
    if (!json || fread(json, 1, length, file) != (size_t)length)
        goto invalid;
    json[length] = '\0';
    if (!plain_json_structure(json, length))
        goto invalid;
    doc = bson_new_from_json((uint8_t *)json, length, &bson_error);
    if (!doc || !keys_valid(doc,
       "|schemaVersion||postgresMajor||systemIdentifier||timeline||documentdbVersion||validFromLsn||validToLsn||relations|", 0) ||
        !integer(doc, "schemaVersion", 2, &value) ||
        (value != 1 && value != 2) ||
        !integer(doc, "postgresMajor", 18, &value) || value != PG_VERSION_NUM / 10000 ||
        !(system = string_value(doc, "systemIdentifier")) ||
        !(version = string_value(doc, "documentdbVersion")) ||
        !integer(doc, "timeline", UINT32_MAX, &value) || !value)
        goto invalid;
    if (!integer(doc, "schemaVersion", 2, &value))
        goto invalid;
    schema_version = (unsigned)value;
    m->schema_version = schema_version;
    m->documentdb_version = strdup(version);
    if (!m->documentdb_version)
        goto invalid;
    if (schema_version == 2)
    {
        unsigned natts;
        const char *fingerprint;
        if (!audit_catalog_descriptor(version, &natts, &fingerprint,
                                      error, size))
            goto invalid;
    }
    if (!integer(doc, "timeline", UINT32_MAX, &value) || !value)
        goto invalid;
    m->timeline = (uint32)value;
    for (const char *p = system; *p; p++)
        if (*p < '0' || *p > '9')
            goto invalid;
    errno = 0;
    m->system_identifier = strtoull(system, NULL, 10);
    if (errno || !m->system_identifier ||
        !parse_lsn(string_value(doc, "validFromLsn"), &m->from) ||
        !parse_lsn(string_value(doc, "validToLsn"), &m->to) || m->from >= m->to ||
        !bson_iter_init_find(&it, doc, "relations") || !BSON_ITER_HOLDS_ARRAY(&it) ||
        !bson_iter_recurse(&it, &entries))
        goto invalid;
    while (bson_iter_next(&entries))
    {
        uint32_t bytes_length;
        const uint8_t *bytes;
        bson_t entry;
        AuditRelation relation = {0};
        AuditRelation *grown;
        const char *database = NULL, *collection = NULL, *kind = NULL;
        if (!BSON_ITER_HOLDS_DOCUMENT(&entries))
            goto invalid;
        bson_iter_document(&entries, &bytes_length, &bytes);
        if (!bson_init_static(&entry, bytes, bytes_length) ||
            !keys_valid(&entry, schema_version == 1 ?
                "|tblspaceOid||databaseOid||relfilenode||collectionId||database||collection|" :
                "|kind||tblspaceOid||databaseOid||relfilenode||collectionId||database||collection|", 0) ||
            !integer(&entry, "tblspaceOid", UINT32_MAX, &value) || !value)
            goto invalid;
        relation.tablespace = value;
        if (!integer(&entry, "databaseOid", UINT32_MAX, &value) || !value)
            goto invalid;
        relation.database_oid = value;
        if (!integer(&entry, "relfilenode", UINT32_MAX, &value) || !value)
            goto invalid;
        relation.relfilenode = value;
        if (schema_version == 1)
            relation.kind = AUDIT_RELATION_DOCUMENT;
        else
        {
            kind = string_value(&entry, "kind");
            if (!kind)
                goto invalid;
            if (!strcmp(kind, "document"))
                relation.kind = AUDIT_RELATION_DOCUMENT;
            else if (!strcmp(kind, "collections_catalog"))
                relation.kind = AUDIT_RELATION_COLLECTIONS_CATALOG;
            else
                goto invalid;
        }
        if (relation.kind == AUDIT_RELATION_DOCUMENT)
        {
            if (!integer(&entry, "collectionId", INT64_MAX, &value) || !value ||
                !(database = string_value(&entry, "database")) ||
                !(collection = string_value(&entry, "collection")))
                goto invalid;
            relation.collection_id = (int64)value;
        }
        else if (bson_has_field(&entry, "collectionId") ||
                 bson_has_field(&entry, "database") ||
                 bson_has_field(&entry, "collection"))
            goto invalid;
        for (size_t i = 0; i < m->count; i++)
            if (m->relations[i].tablespace == relation.tablespace &&
                m->relations[i].database_oid == relation.database_oid &&
                m->relations[i].relfilenode == relation.relfilenode)
                goto invalid;
        if (m->count >= 100000)
            goto invalid;
        grown = realloc(m->relations, (m->count + 1) * sizeof(*grown));
        if (!grown)
            goto invalid;
        m->relations = grown;
        relation.database = database ? strdup(database) : NULL;
        relation.collection = collection ? strdup(collection) : NULL;
        if ((database && !relation.database) || (collection && !relation.collection))
        {
            free(relation.database);
            free(relation.collection);
            goto invalid;
        }
        m->relations[m->count++] = relation;
    }
    ok = true;
invalid:
    if (file && fclose(file))
        ok = false;
    free(json);
    if (doc)
        bson_destroy(doc);
    if (!ok)
    {
        audit_manifest_free(m);
        return fail(error, size, "invalid JSON, duplicate/unknown keys, types, bounds, PostgreSQL major, or relation descriptor");
    }
    return true;
}

void
audit_manifest_free(AuditManifest *m)
{
    for (size_t i = 0; i < m->count; i++)
    {
        free(m->relations[i].database);
        free(m->relations[i].collection);
    }
    free(m->relations);
    free(m->documentdb_version);
    memset(m, 0, sizeof(*m));
}

const AuditRelation *
audit_manifest_relation(const AuditManifest *m, uint32 tablespace,
                        uint32 database, uint32 relfilenode, XLogRecPtr lsn)
{
    if (lsn < m->from || lsn >= m->to)
        return NULL;
    for (size_t i = 0; i < m->count; i++)
        if (m->relations[i].tablespace == tablespace &&
            m->relations[i].database_oid == database &&
            m->relations[i].relfilenode == relfilenode)
            return &m->relations[i];
    return NULL;
}
