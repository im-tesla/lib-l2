CXX ?= clang++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra

UNAME_S := $(shell uname -s)
LDFLAGS ?=
ifeq ($(UNAME_S),Linux)
    LDFLAGS += -ldl
endif

TARGET = lib-l2
SRC = src/example.cpp

all: $(TARGET)

$(TARGET): $(SRC) src/libl2.h
	$(CXX) $(CXXFLAGS) -Isrc $(SRC) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean
