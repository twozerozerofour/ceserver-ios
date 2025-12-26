CXX = x86_64-w64-mingw32-g++

TARGET := ios_stacktrace_plugin.dll
SRC := ios_stacktrace_plugin.cpp

CPPFLAGS := -Ice_sdk
CXXFLAGS := -std=c++17 -O2
LDFLAGS := -shared -static -static-libgcc -static-libstdc++ -s

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
