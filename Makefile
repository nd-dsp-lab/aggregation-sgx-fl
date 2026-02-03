CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -march=native -pthread -fopenmp \
           -Wno-unused-parameter -Wno-missing-field-initializers
INCLUDES = -I/usr/local/include/openfhe -I/usr/local/include/openfhe/third-party/include -I/usr/local/include/openfhe/core -I/usr/local/include/openfhe/pke -I/usr/local/include/openfhe/binfhe
LDFLAGS = -L/usr/local/lib
LIBS = -lOPENFHEpke -lOPENFHEcore -lssl -lcrypto -lgomp

TERSE_OBJECTS = terse.o
TARGETS = client server trusted aes_client aes_trusted setup

.PHONY: all sgx clean cleanall

all: $(TARGETS)

# TERSE Protocol
terse.o: terse.cpp terse.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

client: $(TERSE_OBJECTS) client.o
	$(CXX) $(CXXFLAGS) $(TERSE_OBJECTS) client.o -o client $(LDFLAGS) $(LIBS)

client.o: client.cpp terse.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

server: $(TERSE_OBJECTS) server.o
	$(CXX) $(CXXFLAGS) $(TERSE_OBJECTS) server.o -o server $(LDFLAGS) $(LIBS)

server.o: server.cpp terse.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

trusted: $(TERSE_OBJECTS) trusted.o
	$(CXX) $(CXXFLAGS) $(TERSE_OBJECTS) trusted.o -o trusted $(LDFLAGS) $(LIBS)

trusted.o: trusted.cpp terse.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

setup: $(TERSE_OBJECTS) setup.o
	$(CXX) $(CXXFLAGS) $(TERSE_OBJECTS) setup.o -o setup $(LDFLAGS) $(LIBS)

setup.o: setup.cpp terse.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# AES Protocol
aes_client: aes_client.o
	$(CXX) $(CXXFLAGS) aes_client.o -o aes_client $(LIBS)

aes_client.o: aes_client.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

aes_trusted: aes_trusted.o
	$(CXX) $(CXXFLAGS) aes_trusted.o -o aes_trusted $(LIBS)

aes_trusted.o: aes_trusted.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# SGX Targets
sgx: trusted.manifest.sgx aes_trusted.manifest.sgx setup.manifest.sgx

trusted.manifest: trusted.manifest.template
	gramine-manifest -Dlog_level=error -Darch_libdir=/lib/x86_64-linux-gnu -Dexecdir=$(shell pwd) $< $@

trusted.manifest.sgx: trusted.manifest trusted
	gramine-sgx-sign --manifest $< --output $@

aes_trusted.manifest: aes_trusted.manifest.template
	gramine-manifest -Dlog_level=error -Darch_libdir=/lib/x86_64-linux-gnu -Dexecdir=$(shell pwd) $< $@

aes_trusted.manifest.sgx: aes_trusted.manifest aes_trusted
	gramine-sgx-sign --manifest $< --output $@

setup.manifest: setup.manifest.template
	gramine-manifest -Dlog_level=error -Darch_libdir=/lib/x86_64-linux-gnu -Dexecdir=$(shell pwd) $< $@

setup.manifest.sgx: setup.manifest setup
	gramine-sgx-sign --manifest $< --output $@

# Clean targets
clean:
	rm -f *.o $(TARGETS)
	rm -f *.manifest *.manifest.sgx *.sig *.token

cleanall: clean
	rm -rf data/
