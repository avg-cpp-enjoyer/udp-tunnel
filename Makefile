CC       ?= cc
CFLAGS   ?= -O2 -g -Wall -Wextra -Wpedantic -std=c11
CFLAGS   += -D_GNU_SOURCE
LDLIBS   += -lssl -lcrypto

LOG_LEVEL ?= LOG_INFO
CFLAGS   += -DLOG_LEVEL=$(LOG_LEVEL)

BIN      := tunnel
TEST_BIN := test_crypto

SRCS     := src/main.c src/crypto.c src/tun.c
OBJS     := $(SRCS:.c=.o)

TEST_SRCS := tests/test_crypto.c src/crypto.c
TEST_OBJS := $(TEST_SRCS:.c=.o)

.PHONY: all clean test test-san debug

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(TEST_BIN): $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJS) $(LDLIBS)

test: $(TEST_BIN)
	./$(TEST_BIN)

test-san: CFLAGS += -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
test-san: clean $(TEST_BIN)
	./$(TEST_BIN)
	$(MAKE) clean

debug: CFLAGS += -DLOG_LEVEL=LOG_DEBUG -O0 -g3
debug: clean all

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(OBJS:.o=.d)
-include $(TEST_OBJS:.o=.d)

clean:
	rm -f $(OBJS) $(TEST_OBJS)
	rm -f $(OBJS:.o=.d) $(TEST_OBJS:.o=.d)
	rm -f $(BIN) $(TEST_BIN)
