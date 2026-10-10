PG_MAJOR ?= 18
SUPPORTED_MAJORS := 16 17 18
ifneq ($(words $(PG_MAJOR)),1)
$(error PG_MAJOR must be one major: 16, 17, or 18)
endif
ifeq ($(filter $(PG_MAJOR),$(SUPPORTED_MAJORS)),)
$(error PG_MAJOR must be 16, 17, or 18)
endif

PG_ROOT := build/pg$(PG_MAJOR)
PG_SOURCE := $(PG_ROOT)/postgresql
BINARY := $(PG_ROOT)/documentdb-wal-audit
NATIVE_TEST := $(PG_ROOT)/test_decoder
CATALOG_TEST := $(PG_ROOT)/test_catalog
UPDATE_TEST := $(PG_ROOT)/test_update_reconstruction
SOURCES := src/main.c src/wal_reader.c src/decoder.c src/manifest.c src/bson_decoder.c src/catalog.c src/page_state.c src/update_reconstruction.c
OBJECTS := $(patsubst src/%.c,$(PG_ROOT)/%.o,$(SOURCES))
CPPFLAGS += -DFRONTEND -Iinclude -Iprivateinclude -I$(PG_SOURCE)/src/include $(shell pkg-config --cflags libbson-1.0 sqlite3)
CFLAGS ?= -O2 -g
CORE_CFLAGS := -std=gnu11 -Wall -Wextra -Wno-unused-parameter -ffunction-sections -fdata-sections
LDLIBS += $(shell pkg-config --libs libbson-1.0 sqlite3) -lm

.PHONY: all test native-test clean postgres FORCE
all: $(BINARY)
postgres: $(PG_ROOT)/.postgres-ready

$(PG_ROOT)/.postgres-ready: scripts/build-postgres.sh
	@mkdir -p $(PG_ROOT)
	+sh scripts/build-postgres.sh $(PG_MAJOR)
	@touch $@

$(PG_ROOT)/.audit-flags: FORCE | $(PG_ROOT)/.postgres-ready
	@printf '%s\n' '$(CC) $(CPPFLAGS) $(CFLAGS) $(CORE_CFLAGS) $(LDFLAGS) $(LDLIBS)' > $@.new
	@cmp -s $@.new $@ || mv $@.new $@
	@rm -f $@.new

$(PG_ROOT)/%.o: src/%.c include/audit.h $(PG_ROOT)/.postgres-ready $(PG_ROOT)/.audit-flags
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CORE_CFLAGS) -MMD -MP -c $< -o $@

$(PG_ROOT)/xlogreader.o: $(PG_ROOT)/.postgres-ready $(PG_ROOT)/.audit-flags
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CORE_CFLAGS) -c $(PG_SOURCE)/src/backend/access/transam/xlogreader.c -o $@

$(PG_ROOT)/xactdesc.o: $(PG_ROOT)/.postgres-ready $(PG_ROOT)/.audit-flags
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CORE_CFLAGS) -c $(PG_SOURCE)/src/backend/access/rmgrdesc/xactdesc.c -o $@

$(BINARY): $(OBJECTS) $(PG_ROOT)/xlogreader.o $(PG_ROOT)/xactdesc.o
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--gc-sections $^ $(PG_SOURCE)/src/common/libpgcommon.a $(PG_SOURCE)/src/port/libpgport.a $(LDLIBS) -o $@

$(PG_ROOT)/test_decoder.o: tests/test_decoder.c include/audit.h privateinclude/audit_private.h $(PG_ROOT)/.postgres-ready $(PG_ROOT)/.audit-flags
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CORE_CFLAGS) -UNDEBUG -MMD -MP -c $< -o $@

$(NATIVE_TEST): $(PG_ROOT)/test_decoder.o $(PG_ROOT)/bson_decoder.o
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--gc-sections $^ $(PG_SOURCE)/src/common/libpgcommon.a $(PG_SOURCE)/src/port/libpgport.a $(LDLIBS) -o $@

$(PG_ROOT)/test_catalog.o: tests/test_catalog.c include/audit.h include/catalog.h $(PG_ROOT)/.postgres-ready $(PG_ROOT)/.audit-flags
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CORE_CFLAGS) -UNDEBUG -MMD -MP -c $< -o $@

$(CATALOG_TEST): $(PG_ROOT)/test_catalog.o $(PG_ROOT)/catalog.o $(PG_ROOT)/manifest.o
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--gc-sections $^ $(PG_SOURCE)/src/common/libpgcommon.a $(PG_SOURCE)/src/port/libpgport.a $(LDLIBS) -o $@

$(PG_ROOT)/test_update_reconstruction.o: tests/test_update_reconstruction.c include/page_state.h include/update_reconstruction.h $(PG_ROOT)/.postgres-ready $(PG_ROOT)/.audit-flags
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CORE_CFLAGS) -UNDEBUG -MMD -MP -c $< -o $@

$(UPDATE_TEST): $(PG_ROOT)/test_update_reconstruction.o $(PG_ROOT)/page_state.o $(PG_ROOT)/update_reconstruction.o
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--gc-sections $^ $(PG_SOURCE)/src/common/libpgcommon.a $(PG_SOURCE)/src/port/libpgport.a $(LDLIBS) -o $@

native-test: $(NATIVE_TEST) $(CATALOG_TEST) $(UPDATE_TEST)
	$(NATIVE_TEST)
	$(CATALOG_TEST)
	$(UPDATE_TEST)

test: $(BINARY) native-test
	python3 tests/test_integration.py --binary $(BINARY) --pg-major $(PG_MAJOR)

clean:
	rm -rf $(PG_ROOT)

-include $(OBJECTS:.o=.d) $(PG_ROOT)/test_decoder.d $(PG_ROOT)/test_catalog.d $(PG_ROOT)/test_update_reconstruction.d
