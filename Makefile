CXX      := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -O2 -pthread
# Suppress GCC 13 false-positives in fmt/spdlog headers (stl_algobase.h)
CXXFLAGS += -Wno-array-bounds -Wno-stringop-overflow
INCLUDES := -Iinclude
LDFLAGS  :=

# ── Static vs shared linking ─────────────────────────────────────────
# Usage: make STATIC=1 STATIC_PREFIX=/opt/static-amd64
#
# The CI builds fmt, spdlog and curl from source into STATIC_PREFIX.
# Curl is built *without* SSH/GSSAPI/LDAP/RTMP/PSL so its .a has no
# unresolvable transitive deps.  We use pkg-config --static from
# that prefix to get the right flags automatically, then append any
# remaining transitive static deps that pkg-config may miss.
# ─────────────────────────────────────────────────────────────────────
STATIC_PREFIX ?= /usr/local

ifdef STATIC
  LDFLAGS  += -static
  # Add our prefix to include and library search paths
  CXXFLAGS += -I$(STATIC_PREFIX)/include
  LDFLAGS  += -L$(STATIC_PREFIX)/lib

  # spdlog/fmt definitions (static, not shared)
  CXXFLAGS += -DSPDLOG_COMPILED_LIB -DSPDLOG_FMT_EXTERNAL

  # pkg-config flags from system packages (argon2, openssl, etc.)
  CXXFLAGS += $(shell pkg-config --cflags libargon2 nlohmann_json openssl 2>/dev/null)

  # Use our from-source curl's pkg-config for --static resolution
  CURL_STATIC_LIBS := $(shell PKG_CONFIG_PATH=$(STATIC_PREFIX)/lib/pkgconfig pkg-config --static --libs libcurl 2>/dev/null)

  LIBS := -lspdlog -lfmt \
          -largon2 \
          $(CURL_STATIC_LIBS) \
          -lbrotlicommon \
          -lidn2 -lunistring \
          -lssl -lcrypto \
          -luuid -lpthread -lrt -ldl
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
