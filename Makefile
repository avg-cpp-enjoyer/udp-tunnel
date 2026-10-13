CC       ?= cc
CFLAGS   ?= -O2 -g -Wall -Wextra -Wpedantic -std=c11
CFLAGS   += -D_GNU_SOURCE
LDLIBS   += -lssl -lcrypto

LOG_LEVEL ?= LOG_INFO
CFLAGS   += -DLOG_LEVEL=$(LOG_LEVEL)

BIN             := tunnel
TEST_CRYPTO     := test_crypto
TEST_HANDSHAKE  := test_handshake

SRCS     := src/main.c src/crypto.c src/tun.c src/handshake.c
OBJS     := $(SRCS:.c=.o)

TEST_CRYPTO_SRCS := tests/test_crypto.c src/crypto.c
TEST_CRYPTO_OBJS := $(TEST_CRYPTO_SRCS:.c=.o)

TEST_HANDSHAKE_SRCS := tests/test_handshake.c src/handshake.c
TEST_HANDSHAKE_OBJS := $(TEST_HANDSHAKE_SRCS:.c=.o)

.PHONY: all clean test test-san debug

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(TEST_CRYPTO): $(TEST_CRYPTO_OBJS)
	$(CC) $(CFLAGS) -o $@ $(TEST_CRYPTO_OBJS) $(LDLIBS)

$(TEST_HANDSHAKE): $(TEST_HANDSHAKE_OBJS)
	$(CC) $(CFLAGS) -o $@ $(TEST_HANDSHAKE_OBJS) $(LDLIBS)

test: $(TEST_CRYPTO) $(TEST_HANDSHAKE)
	./$(TEST_CRYPTO)
	./$(TEST_HANDSHAKE)

test-san: CFLAGS += -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
test-san: clean $(TEST_CRYPTO) $(TEST_HANDSHAKE)
	./$(TEST_CRYPTO)
	./$(TEST_HANDSHAKE)
	$(MAKE) clean

debug: CFLAGS += -DLOG_LEVEL=LOG_DEBUG -O0 -g3
debug: clean all

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(OBJS:.o=.d)
-include $(TEST_CRYPTO_OBJS:.o=.d)
-include $(TEST_HANDSHAKE_OBJS:.o=.d)

clean:
	rm -f $(OBJS) $(TEST_CRYPTO_OBJS) $(TEST_HANDSHAKE_OBJS)
	rm -f $(OBJS:.o=.d) $(TEST_CRYPTO_OBJS:.o=.d) $(TEST_HANDSHAKE_OBJS:.o=.d)
	rm -f $(BIN) $(TEST_CRYPTO) $(TEST_HANDSHAKE)
