genrsa: genrsa.c rsa.c der.c
	gcc -o genrsa rsa.c genrsa.c der.c -lgmp
