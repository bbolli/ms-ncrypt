CXXFLAGS = -Og -Wall -Wextra -pedantic -Wconversion -std=c++20
LDLIBS = -lncrypt -lcrypto -lfmt

enum: enum.cpp
