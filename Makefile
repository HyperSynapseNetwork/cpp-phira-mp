CXX      := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -O2 -pthread
# Suppress GCC 13 false-positives in fmt/spdlog headers (stl_algobase.h)
CXXFLAGS += -Wno-array-bounds -Wno-stringop-overflow
INCLUDES := -Iinclude
LDFLAGS  :=

# ── Static vs shared linking ─────────────────────────────────────────
# Usage: make STATIC=1
#   Requires .a static archives for ALL libs. The CI builds fmt & spdlog
#   from source and installs them to /usr/local. For other libs we use
#   the distro -dev packages which provide .a files on Ubuntu 24.04.
#
# The static link line is explicit (not from pkg-config --static) to
# avoid pulling in Kerberos/LDAP/SSH/RTMP which have no .a on Ubuntu.
# ─────────────────────────────────────────────────────────────────────
ifdef STATIC
  LDFLAGS  += -static
  # spdlog/fmt from /usr/local (built from source in CI)
  CXXFLAGS += -DSPDLOG_COMPILED_LIB -DSPDLOG_FMT_EXTERNAL
  CXXFLAGS += $(shell pkg-config --cflags libargon2 nlohmann_json openssl libcurl 2>/dev/null)
  # Explicit static link order — all deps that have .a on Ubuntu 24.04
  LIBS := -lspdlog -lfmt \
          -largon2 \
          -lcurl -lnghttp2 -lpsl -lidn2 -lunistring \
          -lssl -lcrypto \
          -lzstd -lbrotlidec -lbrotlicommon \
          -lz -luuid -lpthread -lrt -ldl
else
  CXXFLAGS += $(shell pkg-config --cflags spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null)
  PKG_LIBS := $(shell pkg-config --libs spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null)
  LIBS := $(PKG_LIBS) -luuid -lpthread
endif

SRCS := src/main.cpp src/binary.cpp src/command.cpp src/stream.cpp \
        src/l10n.cpp src/room.cpp src/session.cpp src/server.cpp \
        src/http_server.cpp

OBJS := $(SRCS:.cpp=.o)
TARGET := phira-mp-server

LOCALES_DIR := $(CURDIR)/locales
CXXFLAGS += -DLOCALES_DIR=\"$(LOCALES_DIR)\"

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
