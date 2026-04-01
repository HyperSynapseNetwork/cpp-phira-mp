CXX      := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -O2 -pthread
# Suppress GCC 13 false-positive in fmt/spdlog headers (stl_algobase.h)
CXXFLAGS += -Wno-array-bounds
INCLUDES := -Iinclude
LDFLAGS  :=

# ── Static vs shared linking ─────────────────────────────────────────
ifdef STATIC
  LDFLAGS  += -static
  PKG_STATIC := --static
  # For static spdlog we must NOT define SPDLOG_SHARED_LIB
  CXXFLAGS += $(shell pkg-config --cflags spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null | sed 's/-DSPDLOG_SHARED_LIB//g')
else
  CXXFLAGS += $(shell pkg-config --cflags spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null)
endif

# pkg-config resolves all transitive deps when --static is given
PKG_LIBS := $(shell pkg-config $(PKG_STATIC) --libs spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null)
LIBS := $(PKG_LIBS) -luuid -lpthread

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
