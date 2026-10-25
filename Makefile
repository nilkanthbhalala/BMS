CC = cc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude
LDLIBS = -pthread -lcrypt

SERVER_SOURCES = src/server.c src/audit.c src/store.c src/store_financial.c src/store_admin.c src/store_loans.c src/common.c src/customer.c src/bank_employee.c src/manager.c src/administrator.c
CLIENT_SOURCES = client/client.c src/common.c

.PHONY: all run-server run-client package clean

all: bin/server bin/client

bin/server: $(SERVER_SOURCES) include/bank.h src/store_internal.h src/server_internal.h
	mkdir -p bin
	$(CC) $(CFLAGS) $(SERVER_SOURCES) -o $@ $(LDLIBS)

bin/client: $(CLIENT_SOURCES) include/bank.h
	mkdir -p bin
	$(CC) $(CFLAGS) $(CLIENT_SOURCES) -o $@ $(LDLIBS)

run-server: bin/server
	./bin/server

run-client: bin/client
	./bin/client

package: all
	rm -f ../OnlineBankingOS-Submission.zip
	zip -r ../OnlineBankingOS-Submission.zip Makefile README.md VIVA.md include src client docs bin

clean:
	rm -rf bin build
