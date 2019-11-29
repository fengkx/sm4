CC ?= gcc

ifeq ($(DEBUG), true)
	CFLAGS += -g -D DEBUG
else
	CFLAGS += -O3
endif

all: clean sm4 main

sm4: randombytes
	$(CC) $(CFLAGS) -c sm4.c 

randombytes:
	$(CC) $(CFLAGS) -c randombytes.c

main: sm4 randombytes
	$(CC) -o sm4 $(CFLAGS) sm4.o randombytes.o main.c

clean:
	rm -f sm4 *.o
