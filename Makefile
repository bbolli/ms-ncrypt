CXXFLAGS = -Og -Wall -Wextra -pedantic -Wconversion -std=c++20
LDLIBS = -lncrypt -lcrypto -lfmt -lwsock32 -lws2_32
LDFLAGS = -s -static

enum: enum.cpp
