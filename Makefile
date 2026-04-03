CXX      ?= g++
CXXFLAGS ?= -std=c++20 -Wall -Wextra -O2 -pthread
INCLUDES := -Iinclude
LDFLAGS  ?=
LIBS     ?=
STATIC   ?= 0
TARGET   ?= phira-mp-server

SRCS := src/main.cpp src/binary.cpp src/command.cpp src/stream.cpp \
        src/l10n.cpp src/room.cpp src/session.cpp src/server.cpp \
        src/http_server.cpp

OBJS := $(SRCS:.cpp=.o)

# ── Platform-specific libraries ───────────────────────────────────────
# Windows (MSYS2 / MinGW): use rpcrt4 for UUID, ws2_32 for sockets
# Linux: use libuuid
ifeq ($(OS),Windows_NT)
  PLATFORM_LIBS := -lrpcrt4 -lws2_32
else
  PLATFORM_LIBS := -luuid
endif

# ── pkg-config detection (skip if LIBS already provided externally) ───
ifeq ($(LIBS),)
  ifeq ($(STATIC),1)
    PKG_FLAGS := $(shell pkg-config --static --cflags spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null)
    PKG_LIBS  := $(shell pkg-config --static --libs spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null)
  else
    PKG_FLAGS := $(shell pkg-config --cflags spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null)
    PKG_LIBS  := $(shell pkg-config --libs spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null)
  endif
  CXXFLAGS += $(PKG_FLAGS)
  LIBS     := $(PKG_LIBS) $(PLATFORM_LIBS) -lpthread
endif

ifeq ($(STATIC),1)
  LDFLAGS += -static
endif

LOCALES_DIR ?= $(CURDIR)/locales
CXXFLAGS += -DLOCALES_DIR=\"$(LOCALES_DIR)\"

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) $(TARGET).exe
