CC := gcc
CFLAGS := $(shell pkg-config fuse --cflags)
LIBS := $(shell pkg-config fuse --libs)
FUSE_USE_VERSION := 29


CFLAGS := --static -DFUSE_USE_VERSION=$(FUSE_USE_VERSION) $(CFLAGS)
LIBS := $(LIBS) -ldl

exploit: exploit.c
	$(CC) $< -o $@ $(CFLAGS) $(LIBS)


