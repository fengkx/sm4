CC=cc
all: clean sm4 main

sm4:
	cc -g -Og -c sm4.c

main: sm4
	cc -o sm4 -Og -g sm4.o main.c

clean:
	rm -f sm4 *.o
