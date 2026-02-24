CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -O2 -pthread -Iinclude -static
LDFLAGS = -pthread -luuid -lssl -lcrypto -static

SRCDIR = src
INCDIR = include
OBJDIR = obj
TARGET = phira-mp-server

SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SOURCES))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET)

# Dependencies
$(OBJDIR)/main.o: $(INCDIR)/server.h $(INCDIR)/l10n.h $(INCDIR)/ban_manager.h $(INCDIR)/web_server.h $(INCDIR)/ws_server.h
$(OBJDIR)/server.o: $(INCDIR)/server.h $(INCDIR)/session.h $(INCDIR)/commands.h
$(OBJDIR)/session.o: $(INCDIR)/session.h $(INCDIR)/room.h $(INCDIR)/server.h $(INCDIR)/ban_manager.h $(INCDIR)/web_server.h $(INCDIR)/ws_server.h
$(OBJDIR)/room.o: $(INCDIR)/room.h $(INCDIR)/session.h $(INCDIR)/commands.h $(INCDIR)/web_server.h
$(OBJDIR)/l10n.o: $(INCDIR)/l10n.h
$(OBJDIR)/http_client.o: $(INCDIR)/http_client.h
$(OBJDIR)/web_server.o: $(INCDIR)/web_server.h $(INCDIR)/server.h $(INCDIR)/ban_manager.h
$(OBJDIR)/ws_server.o: $(INCDIR)/ws_server.h $(INCDIR)/server.h
