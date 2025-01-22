.PHONY: all clean generate_keys
.DEFAULT_GOAL := all

# ---------- file specification and configuration options ----------

# TODO specify all source files for the server here
SERVERSRC = server.c api.c util.c worker.c database.c ssl-nonblock.c crypto.c

# TODO specify all source files for the client here
CLIENTSRC = client.c api.c ui.c util.c ssl-nonblock.c

# TODO specify all key files that must be generated for the TTP here
# (all in the ttpkeys subdirectory)
TTPKEYS =

# EXAMPLE:
#
# TTPKEYS = ttpkeys/ca-key.pem ttpkeys/ca-cert.pem

# TODO specify all key files that must be generated for the server here
# (all in the serverkeys subdirectory)
SERVERKEYS = serverkeys/server-key.pem serverkeys/server-key-cert.pem serverkeys/random-byte.key

# TODO specify all key files that must be generated for the client here
# (all in the clientkeys subdirectory)
CLIENTKEYS =

# Specify compiler flags here
CFLAGS=-g -Wall -Werror -UDEBUG

# Specify linker flags here
LDFLAGS=-g

# Specify libraries to link to here (these should be sufficient)
LDLIBS=-lsqlite3 -lcrypto -lssl



# ---------- rules to build key files ----------

# TODO add rules to build the key files here. Note that, if one key file
# requires another to be built, you must specify it as a dependency.
# Make sure you use a tab character for indentation of build rules,
# spaces will not work

# EXAMPLE:
#
# ttpkeys/ca-key.pem:
#	openssl genrsa -out ttpkeys/ca-key.pem

# ttpkeys/ca-cert.pem: ttpkeys/ca-key.pem
#	openssl req -new -x509 -key ttpkeys/ca-key.pem -out ttpkeys/ca-cert.pem -nodes -subj '/CN=ca\.example\.com/'

# Generate the server private key
serverkeys/server-key.pem:
	openssl genrsa -out $@ 2048

# Generate the server certificate using the private key
serverkeys/server-key-cert.pem: serverkeys/server-key.pem
	openssl req -new -x509 -key $< -out $@ -days 365 -nodes -subj "/CN=localhost"

serverkeys/random-byte.key:
	openssl rand -out $@ 32

# ---------- there is usually no need to modify below this line ----------

# Generate object file lists from source files
CLIENTOBJ = $(CLIENTSRC:.c=.o)
SERVEROBJ = $(SERVERSRC:.c=.o)

# 'make all' builds everything
all: client server generate_keys

# 'make clean' removes everything that was built
clean:
	rm -f server client *.o *.d chat.db
	rm -rf serverkeys clientkeys ttpkeys

# boilerplate for key generation (the actual work is done in the code you add)
generate_keys: $(TTPKEYS) $(SERVERKEYS) $(CLIENTKEYS)

# generate the necessary directories
$(TTPKEYS): ttpkeys

ttpkeys:
	mkdir -p ttpkeys

$(SERVERKEYS): serverkeys

serverkeys:
	mkdir -p serverkeys

$(CLIENTKEYS): clientkeys

clientkeys:
	mkdir -p clientkeys

# link the binaries
client: $(CLIENTOBJ)
	$(CC) $(LDFLAGS) -o $@ $(CLIENTOBJ) $(LDLIBS)

server: $(SERVEROBJ)
	$(CC) $(LDFLAGS) -o $@ $(SERVEROBJ) $(LDLIBS)

# rule to compile object files from C files, while generating a dependency file
# that is used to recompile it if any of the included headers changes
%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# include generated dependency files into the Makefile
DEPS = $(CLIENTSRC:.c=.d) $(SERVERSRC:.c=.d)
-include $(DEPS)
