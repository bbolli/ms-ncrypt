CXXFLAGS = -I. -I/mingw64/include -Og -Wall -Wextra -Wconversion -std=c++20
LDLIBS = -lncrypt -lcrypto -lfmt

enum: enum.cpp
