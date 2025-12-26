CXX = x86_64-w64-mingw32-g++

CXXFLAGS = -shared -static -static-libgcc -static-libstdc++ -s -std=c++17 -Ice_sdk -Illvm/include

TARGET = ios_rtti_plugin.dll

SRC = ios_rtti_plugin.cpp llvm/lib/Demangle/ItaniumDemangle.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
