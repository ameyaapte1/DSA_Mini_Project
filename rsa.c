#include "include.h"

void RSAPrivateKey_init(RSAPrivateKey * key) {
	mpz_init(key->p);
	mpz_init(key->q);
	mpz_init(key->n);
	mpz_init(key->e);
	mpz_init(key->d);
	mpz_init(key->dp);
	mpz_init(key->dq);
	mpz_init(key->iq);
}

void RSAPrivateKey_clear(RSAPrivateKey * key) {
	mpz_clear(key->p);
	mpz_clear(key->q);
	mpz_clear(key->n);
	mpz_clear(key->e);
	mpz_clear(key->d);
	mpz_clear(key->dp);
	mpz_clear(key->dq);
	mpz_clear(key->iq);
}

int getrand(mpz_t x, int bit) {
	int fd, bytes;
	char *mem;
	if(bytes % sizeof(char) != 0 || bit % 256 != 0) {
		fprintf(stderr,
			"rsa:bit size invalid. Must be a multiple of 128 !");
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
	mem[0] |= 1 << (sizeof(char) * 8 - 1);
	mem[0] |= 1 << (sizeof(char) * 8 - 2);
	mpz_import(x, bytes / sizeof(char), 1, sizeof(char), 0, 0, mem);
	close(fd);
	free(mem);
	return 0;
}

int generate_RSAPrivateKey(RSAPrivateKey * key, int bits) {
	mpz_t phin, buf;
	int i = 1, j;

	mpz_init(phin);
	mpz_init(buf);
	mpz_set_ui(key->e, 65535);
	if(getrand(key->p, bits / 2) || getrand(key->q, bits / 2))
		return -1;
	mpz_nextprime(key->p, key->p);
	mpz_nextprime(key->q, key->q);
	mpz_mul(key->n, key->p, key->q);
	mpz_sub(phin, key->n, key->p);
	mpz_sub(phin, phin, key->q);
	mpz_add_ui(phin, phin, 1);

	while(i != 0) {
		mpz_add_ui(key->e, key->e, 2);
		if((j = mpz_invert(key->d, key->e, phin)) != 0)
			i = mpz_divisible_p(phin, key->e);
	}
	mpz_sub_ui(buf, key->p, 1);
	mpz_mod(key->dp, key->d, buf);
	mpz_sub_ui(buf, key->q, 1);
	mpz_mod(key->dq, key->d, buf);
	mpz_invert(key->iq, key->q, key->p);

	mpz_clear(phin);
	mpz_clear(buf);
	return 0;

}

int RSA_Encrypt(char *message, unsigned int len, RSABlock * block,
		RSAPrivateKey * key) {
	mpz_t m, c;
	int key_length;

	key_length = mpz_sizeof(key->n) - 1;
	char *mes;

	mpz_init(m);
	mpz_init(c);
	mes = (char *) calloc(sizeof(char), key_length);

	if(mes == NULL) {
		fprintf(stderr, "Heap exhausted !!\n");
		exit(ENOSPC);
	}

	memcpy(mes, spad, 4);
	memcpy(mes + 4, message, len);
	memcpy(mes + 4 + len, epad, 4);

	mpz_import(m, key_length, 1, sizeof(char), 0, 0, mes);
	gmp_printf("%Zd\n", m);
	mpz_powm_sec(c, m, key->e, key->n);
	gmp_printf("\n%Zd\n\n\n\n", c);

	block->data = (char *) calloc(sizeof(char), mpz_sizeof(c));
	mpz_export(block->data, NULL, 1, sizeof(char), 0, 0, c);
	block->data_length = mpz_sizeof(c);
	block->msg_length = len;

	mpz_clear(c);
	mpz_clear(m);

	free(mes);
	return 0;
}

int RSA_Decrypt(RSABlock * block, char *message, RSAPrivateKey * key) {
	mpz_t c, m;
	char *mes;

	mpz_init(m);
	mpz_init(c);
	mes = (char *) calloc(sizeof(char), mpz_sizeof(key->n));

	if(mes == NULL) {
		fprintf(stderr, "Heap exhausted !!\n");
		exit(ENOSPC);
	}

	mpz_import(c, block->data_length, 1, sizeof(char), 0, 0,
		   block->data);
	mpz_powm_sec(m, c, key->d, key->n);
	gmp_printf("%Zd\n", m);
	gmp_printf("\n%Zd\n\n\n\n", c);
	mpz_export(mes, NULL, 1, sizeof(char), 0, 0, m);
	memcpy(message, mes + 4, block->msg_length);

	free(block->data);
	free(mes);
	mpz_clear(m);
	mpz_clear(c);
	return block->msg_length;
}
