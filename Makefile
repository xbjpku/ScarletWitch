CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=gnu11 -Iinclude
LDFLAGS =

SRCDIR  = src
INCDIR  = include
BUILDDIR = build

TARGETS = $(BUILDDIR)/supervisor $(BUILDDIR)/reload $(BUILDDIR)/sandbox_preload.so

all: $(TARGETS)

# Rust supervisor (replaces C supervisor)
$(BUILDDIR)/supervisor: supervisor/src/*.rs supervisor/Cargo.toml
	cd supervisor && cargo build --release
	cp supervisor/target/release/supervisor $(BUILDDIR)/supervisor

$(BUILDDIR)/sandbox_preload.so: $(SRCDIR)/sandbox_preload.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< $(LDFLAGS)

$(BUILDDIR)/reload: $(SRCDIR)/reload.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Keep C supervisor as reference build target
c-supervisor: $(SRCDIR)/supervisor.c $(SRCDIR)/whitelist.c $(SRCDIR)/cow.c \
              $(INCDIR)/whitelist.h $(INCDIR)/cow.h
	$(CC) $(CFLAGS) -o $(BUILDDIR)/supervisor-c $^ $(LDFLAGS)

clean:
	rm -f $(TARGETS) $(BUILDDIR)/supervisor-c
	cd supervisor && cargo clean 2>/dev/null || true

.PHONY: all clean c-supervisor
