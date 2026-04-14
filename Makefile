CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=gnu11 -Iinclude
LDFLAGS =

SRCDIR  = src
INCDIR  = include
BUILDDIR = build

TARGETS = $(BUILDDIR)/supervisor $(BUILDDIR)/reload $(BUILDDIR)/sandbox_preload.so

all: $(TARGETS)

$(BUILDDIR)/supervisor: $(SRCDIR)/supervisor.c $(SRCDIR)/whitelist.c $(SRCDIR)/cow.c \
                        $(INCDIR)/whitelist.h $(INCDIR)/cow.h
	$(CC) $(CFLAGS) -o $@ $(SRCDIR)/supervisor.c $(SRCDIR)/whitelist.c $(SRCDIR)/cow.c $(LDFLAGS)

$(BUILDDIR)/sandbox_preload.so: $(SRCDIR)/sandbox_preload.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< $(LDFLAGS)

$(BUILDDIR)/reload: $(SRCDIR)/reload.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
