UNAME_S := $(shell uname -s)

# Default flags: Standard C, Position Independent Code, Include local dirs
# We add -Imath/common and -Imath/mceliece for PQClean
CFLAGS_NEW = -O3 -fsanitize=address -Wall -fPIC -I. -Imath/common -Imath/mceliece

ifeq ($(UNAME_S),Darwin)
    # macOS (M1/Intel)
    CC_NEW = clang
    LIB_EXT = dylib
    LDFLAGS_LIB = -dynamiclib -undefined dynamic_lookup
else
    # Linux
    CC_NEW = gcc
    LIB_EXT = so
    LDFLAGS_LIB = -shared
endif

### NEW: Object File Lists ###

# 1. Core McTiny Logic (Same as original)
MCTINY_OBJS = mctiny_cfun.o mctiny_sfun.o packet.o hash.o pacing.o

# 2. PQClean Math Objects (The replacement for Supercop)
MATH_OBJS = math/mceliece/aes256ctr.o \
            math/mceliece/benes.o \
            math/mceliece/bm.o \
            math/mceliece/controlbits.o \
            math/mceliece/crypto_int16.o \
            math/mceliece/crypto_int32.o \
            math/mceliece/crypto_uint16.o \
            math/mceliece/crypto_uint32.o \
            math/mceliece/crypto_uint64.o \
            math/mceliece/decrypt.o \
            math/mceliece/encrypt.o \
            math/mceliece/gf.o \
            math/mceliece/operations.o \
            math/mceliece/pk_gen.o \
            math/mceliece/root.o \
            math/mceliece/sk_gen.o \
            math/mceliece/synd.o \
            math/mceliece/transpose.o \
            math/mceliece/util.o \
            math/common/fips202.o \
            math/common/aes.o \
            math/common/sha2.o \
            math/common/sp800-185.o

# 3. The Bridge & TweetNaCl (Your compatibility layers)
BRIDGE_OBJS = bridge.o tweetnacl.o

# The Shared Library Target (For Haskell)
LIB_TARGET = libmctiny.$(LIB_EXT)

# ORIGINAL: CC=gcc -Wall -O3 -fwrapv -fPIC -fPIE
# MODIFIED: Use our platform-detected CC
CC=$(CC_NEW) $(CFLAGS_NEW)


default: $(LIB_TARGET) mctiny-test mctiny-master mctiny-server mctiny-client

documentation: \
	README.html \
	mctiny.html \
	pacing.html \
	packet.html \
	hash.html

README.html: README.md md2html
	./md2html < README.md > README.html

mctiny-runtest: mctiny-test
	./mctiny-test

# MODIFIED: Updated to link against Bridge, TweetNaCl, and PQClean
mctiny-test: mctiny-test.o $(MCTINY_OBJS) $(MATH_OBJS) $(BRIDGE_OBJS)
	$(CC) -o mctiny-test mctiny-test.o $(MCTINY_OBJS) $(MATH_OBJS) $(BRIDGE_OBJS)

# MODIFIED: Added dependencies on new headers
mctiny-test.o: mctiny-test.c mctiny.h randombytes.h
	$(CC) -c mctiny-test.c

### NEW TARGET: Shared Library for Haskell ###
$(LIB_TARGET): $(MCTINY_OBJS) $(MATH_OBJS) $(BRIDGE_OBJS)
	$(CC) $(LDFLAGS_LIB) -o $(LIB_TARGET) $(MCTINY_OBJS) $(MATH_OBJS) $(BRIDGE_OBJS)

### COMMENTED OUT: Standalone executables we don't need for the Lib ###

mctiny-master: mctiny-master.o hash.o Makefile
	$(CC) -o mctiny-master mctiny-master.o hash.o $(MATH_OBJS) $(BRIDGE_OBJS) $(LIBS)

mctiny-master.o: mctiny-master.c \
mctiny.h hash.h Makefile
	$(CC) -c mctiny-master.c $(INCLUDE)

# mctiny-rotate: mctiny-rotate.o \
# hash.o Makefile $(SUPERCOP)
# 	$(CC) -o mctiny-rotate mctiny-rotate.o hash.o \
# 	$(LIBS)

# mctiny-rotate.o: mctiny-rotate.c \
# mctiny.h hash.h Makefile $(SUPERCOP)
# 	$(CC) -c mctiny-rotate.c $(INCLUDE)

mctiny-server: mctiny-server.o packet.o mctiny_sfun.o hash.o $(MATH_OBJS) $(BRIDGE_OBJS)
	$(CC) -o mctiny-server mctiny-server.o packet.o mctiny_sfun.o hash.o $(MATH_OBJS) $(BRIDGE_OBJS)

mctiny-server.o: mctiny-server.c mctiny.h hash.h packet.h
	$(CC) -c mctiny-server.c

mctiny-client: mctiny-client.o mctiny_cfun.o hash.o packet.o pacing.o $(MATH_OBJS) $(BRIDGE_OBJS)
	$(CC) -o mctiny-client mctiny-client.o mctiny_cfun.o hash.o packet.o pacing.o $(MATH_OBJS) $(BRIDGE_OBJS)

mctiny-client.o: mctiny-client.c mctiny.h hash.h packet.h pacing.h
	$(CC) -c mctiny-client.c

mctiny.html: mctiny.md md2html
	./md2html < mctiny.md > mctiny.html

mctiny.h: mctiny.py
	./mctiny.py > mctiny.h

# MODIFIED: Remove Supercop dep, add header dep
mctiny_cfun.o: mctiny_cfun.c mctiny.h crypto_kem_mceliece6960119.h
	$(CC) -c mctiny_cfun.c


# MODIFIED: Remove Supercop dep, add header dep
mctiny_sfun.o: mctiny_sfun.c mctiny.h crypto_stream_xsalsa20.h
	$(CC) -c mctiny_sfun.c

pacing.html: pacing.md md2html
	./md2html < pacing.md > pacing.html

pacing.o: pacing.c Makefile
	$(CC) -c pacing.c

packet.html: packet.md md2html
	./md2html < packet.md > packet.html

packet.o: packet.c Makefile
	$(CC) -c packet.c

hash.html: hash.md md2html
	./md2html < hash.md > hash.html

# MODIFIED: Add header dep for SHAKE256
hash.o: hash.c crypto_hash_shake256.h
	$(CC) -c hash.c

# $(SUPERCOP): supercop-build supercop/downloaded
# 	./supercop-build

# supercop/downloaded: supercop-download
# 	./supercop-download


### NEW: Clean rule for new objects ###
clean:
	rm -f *.o math/mceliece/*.o math/common/*.o *.dylib *.so mctiny.h mctiny-test mctiny-server mctiny-client