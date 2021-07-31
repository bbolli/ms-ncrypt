CXXFLAGS = -I. -I/mingw64/include -Og -Wall -Wextra -std=c++17
LDLIBS = -lncrypt -lcrypto

enum: enum.cpp
