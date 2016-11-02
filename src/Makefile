all: genrsa enc 

genrsa: genrsa.c rsa.o der.o include.h base64.o pem.o
	gcc -o ../bin/genrsa rsa.o genrsa.c der.o base64.o pem.o -lgmp -Wall
enc: enc.c der.o rsa.o base64.o pem.o
	gcc -o ../bin/enc enc.c rsa.o der.o base64.o pem.o -lgmp -Wall 
rsa.o: rsa.c
	gcc -c rsa.c -lgmp -Wall 
der.o: der.c 
	gcc -c der.c -lgmp -Wall 
base64.o: base64.h base64.c
	gcc -c base64.c -Wall 
pem.o: pem.c base64.c der.c rsa.c 
	gcc -c pem.c base64.c der.c rsa.c -lgmp	-Wall 
clean:
	rm *.o 
