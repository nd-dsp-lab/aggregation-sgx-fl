# Makefile
CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -march=native -fopenmp
INCLUDES = -I/usr/local/include/openfhe -I/usr/local/include/openfhe/core -I/usr/local/include/openfhe/pke -I/usr/local/include/openfhe/binfhe
LDFLAGS = -L/usr/local/lib
LIBS = -lOPENFHEpke -lOPENFHEcore -lOPENFHEbinfhe -lcrypto

TERSE_SOURCES = terse.cpp
TERSE_OBJECTS = $(TERSE_SOURCES:.cpp=.o)

TARGETS = client server trusted aes_client aes_trusted setup

# Gramine-specific variables
ARCH_LIBDIR ?= /lib/x86_64-linux-gnu
SGX_SIGNER_KEY ?= $(HOME)/.config/gramine/enclave-key.pem

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all sgx clean

all: $(TARGETS)

sgx: $(SGX_SIGNER_KEY) trusted.manifest.sgx trusted.sig aes_trusted.manifest.sgx aes_trusted.sig setup.manifest.sgx setup.sig

# TERSE targets
client: $(TERSE_OBJECTS) client.o
	$(CXX) $(CXXFLAGS) $(TERSE_OBJECTS) client.o -o client $(LDFLAGS) $(LIBS)

server: $(TERSE_OBJECTS) server.o
	$(CXX) $(CXXFLAGS) $(TERSE_OBJECTS) server.o -o server $(LDFLAGS) $(LIBS)

trusted: $(TERSE_OBJECTS) trusted.o
	$(CXX) $(CXXFLAGS) $(TERSE_OBJECTS) trusted.o -o trusted $(LDFLAGS) $(LIBS)

setup: $(TERSE_OBJECTS) setup.o
	$(CXX) $(CXXFLAGS) $(TERSE_OBJECTS) setup.o -o setup $(LDFLAGS) $(LIBS)

# AES targets
aes_client: aes_client.o
	$(CXX) $(CXXFLAGS) aes_client.o -o aes_client $(LDFLAGS) -lcrypto

aes_trusted: aes_trusted.o
	$(CXX) $(CXXFLAGS) aes_trusted.o -o aes_trusted $(LDFLAGS) -lcrypto

# Object files
%.o: %.cpp terse.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

aes_client.o: aes_client.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

aes_trusted.o: aes_trusted.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Generate SGX signing key automatically if it doesn't exist
$(SGX_SIGNER_KEY):
	@echo "Generating SGX signing key at $(SGX_SIGNER_KEY)..."
	@mkdir -p $(dir $(SGX_SIGNER_KEY))
	@gramine-sgx-gen-private-key $(SGX_SIGNER_KEY)
	@echo "Key generated successfully!"

# TERSE Gramine manifests
trusted.manifest: trusted.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dexecdir=$(shell pwd) \
		$< > $@

trusted.manifest.sgx trusted.sig: trusted.manifest trusted $(SGX_SIGNER_KEY)
	gramine-sgx-sign \
		--manifest $< \
		--output trusted.manifest.sgx \
		--key $(SGX_SIGNER_KEY)

setup.manifest: setup.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dexecdir=$(shell pwd) \
		$< > $@

setup.manifest.sgx setup.sig: setup.manifest setup $(SGX_SIGNER_KEY)
	gramine-sgx-sign \
		--manifest $< \
		--output setup.manifest.sgx \
		--key $(SGX_SIGNER_KEY)

# AES Gramine manifests
aes_trusted.manifest: aes_trusted.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dexecdir=$(shell pwd) \
		$< > $@

aes_trusted.manifest.sgx aes_trusted.sig: aes_trusted.manifest aes_trusted $(SGX_SIGNER_KEY)
	gramine-sgx-sign \
		--manifest $< \
		--output aes_trusted.manifest.sgx \
		--key $(SGX_SIGNER_KEY)

clean:
	rm -f *.o $(TARGETS)
	rm -f *.manifest *.manifest.sgx *.sig *.token
	rm -rf data/

.PHONY: all sgx clean
