CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS  = -lpcap -lpthread
TARGET   = ipk-l4-scan
SRC      = main.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
