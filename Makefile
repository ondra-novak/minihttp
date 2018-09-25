CXXFLAGS=-O3
INSTALL_PROGRAM=install
DESTDIR=/usr/local
BINDIR=/bin

all : minihttp

minihttp : src/minihttp.cpp Makefile
	$(CXX) $(CXXFLAGS) -o minihttp -Wall -std=c++17  src/minihttp.cpp -lpthread -lstdc++fs
	

install: all
	$(INSTALL_PROGRAM) minihttp $(DESTDIR)$(BINDIR)/minihttp
	$(INSTALL_PROGRAM) minihttp_proxy $(DESTDIR)$(BINDIR)/minihttp_proxy 

clean:
	rm -rf minihttp
