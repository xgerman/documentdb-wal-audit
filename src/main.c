#include "postgres_fe.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>

#include "wal_reader.h"

static void
usage(FILE *out)
{
    fprintf(out,
            "documentdb-wal-audit (PostgreSQL %d native XLogReader)\n"
            "Usage: documentdb-wal-audit [options] WALFILE...\n"
            "       documentdb-wal-audit [options] --wal-dir DIRECTORY\n"
            "  --format text|jsonl             Output format (default text)\n"
            "  --postgres-major N              Must match this build (%d)\n"
            "  --from-lsn HEX/HEX               Inclusive record boundary\n"
            "  --to-lsn HEX/HEX                 Exclusive record boundary\n"
            "  --transaction DECIMAL           Filter transaction ID\n"
            "  --manifest FILE                 Versioned relation manifest\n"
            "  --spill-dir DIRECTORY           Bounded transaction spill storage\n"
            "  --cache FILE                    Persistent catalog cache\n"
            "  --rebuild-cache                 Rebuild and atomically replace --cache\n"
            "  --no-persistent-cache           Use process-local catalog/page state (default)\n"
            "  --ephemeral-cache DIRECTORY     Private disposable catalog/page cache\n"
            "  --max-record-bytes N             Default 67108864\n"
            "  --max-transaction-bytes N        Default 67108864\n"
            "  --max-document-bytes N           Default 16777216\n"
            "  --include-aborted --strict --show-postgres-records\n"
            "  --redact-documents --version --help\n",
            PG_VERSION_NUM / 10000, PG_VERSION_NUM / 10000);
}

static bool
parse_decimal(const char *text, uint64 minimum, uint64 maximum, uint64 *value)
{
    char *end;
    unsigned long long n;

    if (!text || !*text)
        return false;
    for (const char *p = text; *p; ++p)
        if (*p < '0' || *p > '9')
            return false;
    errno = 0;
    n = strtoull(text, &end, 10);
    if (errno || *end || n < minimum || n > maximum)
        return false;
    *value = n;
    return true;
}

static bool
parse_lsn(const char *text, XLogRecPtr *value)
{
    uint32 parts[2] = {0, 0};
    const char *p = text;

    for (int i = 0; i < 2; ++i)
    {
        int count = 0;
        while (*p && *p != '/')
        {
            unsigned digit;
            if (*p >= '0' && *p <= '9') digit = *p - '0';
            else if (*p >= 'A' && *p <= 'F') digit = *p - 'A' + 10;
            else if (*p >= 'a' && *p <= 'f') digit = *p - 'a' + 10;
            else return false;
            if (++count > 8) return false;
            parts[i] = (parts[i] << 4) | digit;
            ++p;
        }
        if (!count) return false;
        if (i == 0)
        {
            if (*p != '/') return false;
            ++p;
        }
        else if (*p) return false;
    }
    *value = ((uint64) parts[0] << 32) | parts[1];
    return true;
}

int
main(int argc, char **argv)
{
    enum { OPT_FORMAT = 256, OPT_MAJOR, OPT_FROM, OPT_TO, OPT_TRANSACTION,
           OPT_MANIFEST, OPT_SPILL, OPT_RECORD, OPT_TX_BYTES, OPT_DOC_BYTES,
           OPT_CACHE, OPT_REBUILD_CACHE, OPT_NO_CACHE, OPT_EPHEMERAL_CACHE,
           OPT_ABORTED, OPT_STRICT, OPT_POSTGRES, OPT_REDACT, OPT_VERSION };
    static const struct option long_options[] = {
        {"wal-dir", required_argument, NULL, 'w'},
        {"format", required_argument, NULL, OPT_FORMAT},
        {"postgres-major", required_argument, NULL, OPT_MAJOR},
        {"from-lsn", required_argument, NULL, OPT_FROM},
        {"to-lsn", required_argument, NULL, OPT_TO},
        {"transaction", required_argument, NULL, OPT_TRANSACTION},
        {"manifest", required_argument, NULL, OPT_MANIFEST},
        {"spill-dir", required_argument, NULL, OPT_SPILL},
        {"cache", required_argument, NULL, OPT_CACHE},
        {"rebuild-cache", no_argument, NULL, OPT_REBUILD_CACHE},
        {"no-persistent-cache", no_argument, NULL, OPT_NO_CACHE},
        {"ephemeral-cache", required_argument, NULL, OPT_EPHEMERAL_CACHE},
        {"max-record-bytes", required_argument, NULL, OPT_RECORD},
        {"max-transaction-bytes", required_argument, NULL, OPT_TX_BYTES},
        {"max-document-bytes", required_argument, NULL, OPT_DOC_BYTES},
        {"include-aborted", no_argument, NULL, OPT_ABORTED},
        {"strict", no_argument, NULL, OPT_STRICT},
        {"show-postgres-records", no_argument, NULL, OPT_POSTGRES},
        {"redact-documents", no_argument, NULL, OPT_REDACT},
        {"version", no_argument, NULL, OPT_VERSION},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    AuditOptions options = {0};
    const char *wal_dir = NULL;
    uint64 number;
    int opt;

    options.to_lsn = UINT64_MAX;
    options.max_record_bytes = 64 * 1024 * 1024;
    options.max_transaction_bytes = 64 * 1024 * 1024;
    options.max_document_bytes = 16 * 1024 * 1024;
    opterr = 0;
    while ((opt = getopt_long(argc, argv, "hw:", long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case 'h': usage(stdout); return 0;
            case OPT_VERSION:
                printf("documentdb-wal-audit PostgreSQL %s (native XLogReader)\n", PG_VERSION);
                return 0;
            case 'w': wal_dir = optarg; break;
            case OPT_FORMAT:
                if (strcmp(optarg, "jsonl") && strcmp(optarg, "text")) goto invalid;
                options.jsonl = !strcmp(optarg, "jsonl"); break;
            case OPT_MAJOR:
                if (!parse_decimal(optarg, 16, 18, &number) ||
                    number != PG_VERSION_NUM / 10000) goto invalid;
                break;
            case OPT_FROM:
                if (!parse_lsn(optarg, &options.from_lsn)) goto invalid;
                break;
            case OPT_TO:
                if (!parse_lsn(optarg, &options.to_lsn)) goto invalid;
                break;
            case OPT_TRANSACTION:
                if (!parse_decimal(optarg, 1, UINT32_MAX, &number)) goto invalid;
                options.transaction_filter = (TransactionId) number; break;
            case OPT_MANIFEST: options.manifest_path = optarg; break;
            case OPT_SPILL: options.spill_dir = optarg; break;
            case OPT_CACHE: options.catalog_cache_path = optarg; break;
            case OPT_REBUILD_CACHE: options.rebuild_cache = true; break;
            case OPT_NO_CACHE: options.no_persistent_cache = true; break;
            case OPT_EPHEMERAL_CACHE: options.ephemeral_cache_dir = optarg; break;
            case OPT_RECORD:
                if (!parse_decimal(optarg, SizeOfXLogRecord, UINT32_MAX, &number)) goto invalid;
                options.max_record_bytes = number; break;
            case OPT_TX_BYTES:
                if (!parse_decimal(optarg, 1, SIZE_MAX / 2, &number)) goto invalid;
                options.max_transaction_bytes = number; break;
            case OPT_DOC_BYTES:
                if (!parse_decimal(optarg, 1, INT32_MAX, &number)) goto invalid;
                options.max_document_bytes = number; break;
            case OPT_ABORTED: options.include_aborted = true; break;
            case OPT_STRICT: options.strict = true; break;
            case OPT_POSTGRES: options.show_postgres_records = true; break;
            case OPT_REDACT: options.redact_documents = true; break;
            default: goto invalid;
        }
    }
    if ((wal_dir != NULL) == (optind < argc) ||
        options.from_lsn >= options.to_lsn ||
        (wal_dir && !*wal_dir) ||
        (options.manifest_path && !*options.manifest_path) ||
        (options.spill_dir && !*options.spill_dir) ||
        (options.catalog_cache_path && !*options.catalog_cache_path) ||
        (options.ephemeral_cache_dir && !*options.ephemeral_cache_dir) ||
        (options.rebuild_cache && !options.catalog_cache_path) ||
        ((options.catalog_cache_path != NULL) + options.no_persistent_cache +
         (options.ephemeral_cache_dir != NULL) > 1))
        goto invalid;
    return audit_read_wal(&options, wal_dir, argc - optind, argv + optind);

invalid:
    fprintf(stderr, "Invalid arguments (build is PostgreSQL %d). Use --help.\n",
            PG_VERSION_NUM / 10000);
    return 2;
}
