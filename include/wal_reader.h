#ifndef DOCUMENTDB_WAL_READER_H
#define DOCUMENTDB_WAL_READER_H

#include "audit.h"

int audit_read_wal(AuditOptions *options, const char *wal_dir,
                   int path_count, char **paths);

#endif
