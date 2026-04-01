CXX      := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -O2 -pthread
INCLUDES := -Iinclude
LDFLAGS  :=

CXXFLAGS += $(shell pkg-config --cflags spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null)

LIBS := $(shell pkg-config --libs spdlog libargon2 nlohmann_json openssl libcurl 2>/dev/null) \
        -lfmt -luuid -lpthread -lcurl

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
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
