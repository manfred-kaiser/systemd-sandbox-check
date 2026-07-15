CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wconversion -std=c11
STATIC_CFLAGS = $(CFLAGS) -static
SRCS = main.c cli.c probe.c unit_parse.c
BIN = systemd-sandbox-check

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRCS) ssc.h
	$(CC) $(STATIC_CFLAGS) -o $(BIN) $(SRCS)
	strip $(BIN)

clean:
	rm -f $(BIN)
