ARG PG_MAJOR=18

FROM postgres:${PG_MAJOR}-bookworm AS toolchain
ARG PG_MAJOR
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential bison flex pkg-config libbson-dev libsqlite3-dev python3 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV PG_MAJOR=${PG_MAJOR}
ENV PG_BIN=/usr/lib/postgresql/${PG_MAJOR}/bin
WORKDIR /src

FROM toolchain AS build
COPY Makefile ./
COPY scripts/ scripts/
RUN make PG_MAJOR="${PG_MAJOR}" postgres
COPY include/ include/
COPY privateinclude/ privateinclude/
COPY src/ src/
COPY tests/ tests/
RUN make -j2 PG_MAJOR="${PG_MAJOR}" all native-test

FROM build AS test
USER postgres
RUN python3 tests/test_integration.py \
    --binary "build/pg${PG_MAJOR}/documentdb-wal-audit" --pg-major "${PG_MAJOR}"

FROM debian:bookworm-slim AS runtime
ARG PG_MAJOR
RUN apt-get update \
    && apt-get install -y --no-install-recommends libbson-1.0-0 libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/pg${PG_MAJOR}/documentdb-wal-audit /usr/local/bin/documentdb-wal-audit
COPY LICENSE /usr/share/doc/documentdb-wal-audit/LICENSE
COPY --from=build /src/build/pg${PG_MAJOR}/postgresql/COPYRIGHT /usr/share/doc/documentdb-wal-audit/PostgreSQL-COPYRIGHT
USER 65534:65534
WORKDIR /data
ENTRYPOINT ["documentdb-wal-audit"]
CMD ["--help"]
