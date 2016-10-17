all: genrsa enc

genrsa: genrsa.c rsa.o der.o include.h
	gcc -o genrsa rsa.o genrsa.c der.o -lgmp
enc: enc.c der.o rsa.o include.h
	gcc -o enc enc.c rsa.o der.o -lgmp
rsa.o: rsa.c include.h
	gcc -c rsa.c -lgmp
der.o: der.c include.h
	gcc -c der.c -lgmp
