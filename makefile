genrsa: genrsa.c rsa.c der.c
	gcc -o genrsa rsa.c genrsa.c der.c -lgmp
enc: enc.c der.c rsa.c
	gcc -o enc rsa.c rsa.c der.c -lgmp
