#!/bin/sh
set -eu
# Caller flags apply to the audit binary, not PostgreSQL's support build.
# In particular, recursive -B must not force concurrent configure runs.
unset MAKEFLAGS MFLAGS CFLAGS CPPFLAGS LDFLAGS
major=${1:-18}
case "$major" in
    16) digest=df9e823eb22330444e1d48e52cc65135a652a6fdb3ce325e3f08549339f51b99 ;;
    17) digest=7e276131c0fdd6b62588dbad9b3bb24b8c3498d5009328dba59af16e819109de ;;
    18) digest=0d5b903b1e5fe361bca7aa9507519933773eb34266b1357c4e7780fdee6d6078 ;;
    *) echo "Unsupported PostgreSQL major: $major" >&2; exit 2 ;;
esac
version="$major.0"
root="build/pg$major"
source="$root/postgresql"
archive="postgresql-$version.tar.bz2"
mkdir -p "$root"
if [ ! -f "$source/configure" ]; then
    curl --fail --location --silent --show-error "https://ftp.postgresql.org/pub/source/v$version/$archive" -o "$root/$archive"
    curl --fail --location --silent --show-error "https://ftp.postgresql.org/pub/source/v$version/$archive.sha256" -o "$root/$archive.sha256"
    (cd "$root" &&
        test "$(cut -d ' ' -f 1 "$archive.sha256")" = "$digest" &&
        sha256sum -c "$archive.sha256" &&
        tar -xjf "$archive")
    mv "$root/postgresql-$version" "$source"
fi
if [ ! -f "$source/src/include/pg_config.h" ]; then
    (cd "$source" && ./configure --without-icu --without-readline --without-zlib > configure.log)
fi
make -s -C "$source/src/include" all
make -s -C "$source/src/backend" generated-headers
make -s -C "$source/src/port" all
make -s -C "$source/src/common" all
touch "$root/.postgres-ready"
