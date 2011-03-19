CC=gcc

all:
	$(CC) -D_GNU_SOURCE -c kmul.c -o kmul.o

install:
	ar rc libkmul.a kmul.o

clean:
	rm -rf kmul.o libkmul.a
