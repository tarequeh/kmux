CC=gcc

all:
	$(CC) -c kreg.c -o kreg.o
	$(CC) -o kreg kreg.o -L../kmul -lkmul

clean:
	rm -rf kreg.o kreg
