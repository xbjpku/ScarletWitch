CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=gnu11
LDFLAGS =

SRCDIR  = src
BUILDDIR = build

TARGETS = $(BUILDDIR)/supervisor $(BUILDDIR)/reload $(BUILDDIR)/sandbox_preload.so

all: $(TARGETS)

$(BUILDDIR)/supervisor: supervisor/src/*.rs supervisor/Cargo.toml
	cd supervisor && cargo build --release
	cp supervisor/target/release/supervisor $(BUILDDIR)/supervisor

$(BUILDDIR)/sandbox_preload.so: $(SRCDIR)/sandbox_preload.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< $(LDFLAGS)

$(BUILDDIR)/reload: $(SRCDIR)/reload.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)
	cd supervisor && cargo clean 2>/dev/null || true

.PHONY: all clean
