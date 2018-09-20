CXXFLAGS=-O3

all : minihttp minihttp.sh

minihttp : src/minihttp.cpp Makefile
	$(CXX) $(CXXFLAGS) -o minihttp -Wall -std=c++17  src/minihttp.cpp -lpthread -lstdc++fs
	
minihttp.sh : src/minihttp.cpp src/script_hdr.sh  Makefile
	cat src/script_hdr.sh src/minihttp.cpp  > ./minihttp.sh
	chmod +x minihttp.sh

clean:
	rm -rf minihttp.sh minihttp
