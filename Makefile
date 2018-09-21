CXXFLAGS=-O3

all : minihttp

minihttp : src/minihttp.cpp Makefile
	$(CXX) $(CXXFLAGS) -o minihttp -Wall -std=c++17  src/minihttp.cpp -lpthread -lstdc++fs
	

clean:
	rm -rf minihttp
