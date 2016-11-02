/*
 *	RSA library : Helper functions for RSA key eneration
 *      Copyright (C) 2016  Ameya Apte
 *
 *      This program is free software: you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation, either version 3 of the License, or
 *      (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *      along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "include.h"

void RSAPrivateKey_init(RSAPrivateKey * key) {	/*mpz_int numbers initialization */
	mpz_init(key->p);
	mpz_init(key->q);
	mpz_init(key->n);
	mpz_init(key->e);
	mpz_init(key->d);
	mpz_init(key->dp);
	mpz_init(key->dq);
	mpz_init(key->iq);
}

void RSAPrivateKey_clear(RSAPrivateKey * key) {	/*mpz_int numbers free */
	mpz_clear(key->p);
	mpz_clear(key->q);
	mpz_clear(key->n);
	mpz_clear(key->e);
	mpz_clear(key->d);
	mpz_clear(key->dp);
	mpz_clear(key->dq);
	mpz_clear(key->iq);
}

int getrand(mpz_t x, int bit) {	/*This code works only on Linux/BSD based Operating Sysytems\
				   random bytes are fetched from /dev/urandom and converted into a mpz_int */
	int fd, bytes;
	char *mem;
	if(bytes % sizeof(char) != 0 || bit % 256 != 0) {
		fprintf(stderr,
			"rsa:bit size invalid.\n Must be a multiple of 128 !\n");
		return -1;
	}
	bytes = bit / 8;
	mem = (char *) malloc(bytes);
	if((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		perror("rsa:open:/dev/urandom:");
		return -1;
	}
	if(read(fd, mem, bytes) == -1) {
		return -1;
		perror("rsa:read:/dev/urandom: ");
	}
	mem[0] |= 1 << (sizeof(char) * 8 - 1);	/*MSB is set high so that number is at least n bits */
	mem[0] |= 1 << (sizeof(char) * 8 - 2);	/*next MSB is also set high so that the product to 
						   two randoms is twice the number of bits */
	mpz_import(x, bytes / sizeof(char), 1, sizeof(char), 0, 0, mem);
	close(fd);
	free(mem);
	return 0;
}

int generate_RSAPrivateKey(RSAPrivateKey * key, int bits) {	/*Modular Mathematics */
	mpz_t phin, buf;
	int i = 1, j;

	mpz_init(phin);
	mpz_init(buf);
	mpz_set_ui(key->e, 65535);
	if(getrand(key->p, bits / 2) || getrand(key->q, bits / 2))
		return -1;
	mpz_nextprime(key->p, key->p);	/*prime number generation */
	mpz_nextprime(key->q, key->q);
	mpz_mul(key->n, key->p, key->q);	/*modulus */
	mpz_sub(phin, key->n, key->p);
	mpz_sub(phin, phin, key->q);
	mpz_add_ui(phin, phin, 1);

	while(i != 0) {
		mpz_add_ui(key->e, key->e, 2);
		if((j = mpz_invert(key->d, key->e, phin)) != 0)
			i = mpz_divisible_p(phin, key->e);
	}
	mpz_sub_ui(buf, key->p, 1);	/*public key and private key */
	mpz_mod(key->dp, key->d, buf);
	mpz_sub_ui(buf, key->q, 1);
	mpz_mod(key->dq, key->d, buf);
	mpz_invert(key->iq, key->q, key->p);

	mpz_clear(phin);
	mpz_clear(buf);
	return 0;

}

int RSA_Encrypt(char *message, size_t len, RSABlock * block, RSAPrivateKey * key) {	/*This function accepts a char array 
											   and encrypts it along with padding */
	int key_length;

	key_length = mpz_sizeof(key->n) - 1;
	char *mes = NULL;

	mes = (char *) realloc(mes, sizeof(char) * key_length);
	if(mes == NULL) {
		fprintf(stderr, "Heap exhausted !!\n");
		exit(ENOSPC);
	}

	memcpy(mes, spad, 4);	/*Padding */
	memcpy(mes + 4, message, len);
	memcpy(mes + 4 + len, epad, 4);

	mpz_import(block->message, key_length, 1, sizeof(char), 0, 0, mes);
	mpz_powm_sec(block->ciphertext, block->message, key->e, key->n);

	block->msg_length = len;
	free(mes);
	return 0;
}

int RSA_Decrypt(RSABlock * block, char *message, size_t len, RSAPrivateKey * key) {	/*The function decrypts 
											   and removes padding */
	char *mes = NULL;

	mes = (char *) realloc(mes, sizeof(char) * mpz_sizeof(key->n));

	if(mes == NULL) {
		fprintf(stderr, "Heap exhausted !!\n");
		exit(ENOSPC);
	}

	mpz_powm_sec(block->message, block->ciphertext, key->d, key->n);
	mpz_export(mes, NULL, 1, sizeof(char), 0, 0, block->message);
	memcpy(message, mes + 4, len);

	free(mes);
	return len;
}
