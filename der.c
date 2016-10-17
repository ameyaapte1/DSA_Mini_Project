#include "include.h"

/*int main(int argc, char *argv[]) {
	RSAPrivateKey key;
	RSAPrivateKey_init(&key,2048);
	DER_to_RSAPrivateKey("./rsa_test.der", &key);
	RSAPrivateKey_to_DER("./test.der", &key);
	RSAPrivateKey_clear(&key);
	return 0;
}*/

unsigned int mpz_sizeof(const mpz_t num) {
	return mpz_size(num) * mp_bits_per_limb / 8;
}

unsigned int getSizeAsUInt(int fd) {
	int tag, length, buf;

	tag = read_8(fd);
	if(tag != 0x02)
		return -1;
	buf = read_8(fd);
	if(buf == 0x81)
		length = read_8(fd);
	else if(buf == 0x82)
		length = read_16(fd);
	else
		length = buf;
	while(read_8(fd) == 0x00)
		length--;
	lseek(fd, -1, SEEK_CUR);
	return length;

}
int write_Length(uint8_t * der, unsigned long size) {
	write_8(der, 0x02);
	if(size < 256) {
		write_8(der, 0x81);
		write_8(der, (uint8_t) size);
	} else {
		write_8(der, 0x82);
		write_16(der, (uint16_t) size);
	}
	return 0;

}

int write_RSAPrivateKey(uint8_t * der, RSAPrivateKey * key) {
	uint8_t *buf;
	unsigned long size;
	int i;

	buf = (uint8_t *) calloc(sizeof(uint8_t), mpz_sizeof(key->n));

	if(buf == NULL) {
		fprintf(stderr, "Heap exhausted !!\n");
		exit(ENOSPC);
	}

	mpz_export(buf, &size, 1, sizeof(uint8_t), 0, 0, key->n);
	write_Length(der, size);
	for(i = 0; i < size; i++)
		write_8(der, buf[i]);

	buf =
	    (uint8_t *) realloc(buf, sizeof(uint8_t) * mpz_sizeof(key->e));
	mpz_export(buf, &size, 1, sizeof(uint8_t), 0, 0, key->e);
	write_Length(der, size);
	for(i = 0; i < size; i++)
		write_8(der, buf[i]);

	buf =
	    (uint8_t *) realloc(buf, sizeof(uint8_t) * mpz_sizeof(key->d));
	mpz_export(buf, &size, 1, sizeof(uint8_t), 0, 0, key->d);
	write_Length(der, size);
	for(i = 0; i < size; i++)
		write_8(der, buf[i]);

	buf =
	    (uint8_t *) realloc(buf, sizeof(uint8_t) * mpz_sizeof(key->p));
	mpz_export(buf, &size, 1, sizeof(uint8_t), 0, 0, key->p);
	write_Length(der, size);
	for(i = 0; i < size; i++)
		write_8(der, buf[i]);

	buf =
	    (uint8_t *) realloc(buf, sizeof(uint8_t) * mpz_sizeof(key->q));
	mpz_export(buf, &size, 1, sizeof(uint8_t), 0, 0, key->q);
	write_Length(der, size);
	for(i = 0; i < size; i++)
		write_8(der, buf[i]);

	buf =
	    (uint8_t *) realloc(buf,
				sizeof(uint8_t) * mpz_sizeof(key->dp));
	mpz_export(buf, &size, 1, sizeof(uint8_t), 0, 0, key->dp);
	write_Length(der, size);
	for(i = 0; i < size; i++)
		write_8(der, buf[i]);

	buf =
	    (uint8_t *) realloc(buf,
				sizeof(uint8_t) * mpz_sizeof(key->dq));
	mpz_export(buf, &size, 1, sizeof(uint8_t), 0, 0, key->dq);
	write_Length(der, size);
	for(i = 0; i < size; i++)
		write_8(der, buf[i]);

	buf =
	    (uint8_t *) realloc(buf,
				sizeof(uint8_t) * mpz_sizeof(key->iq));
	mpz_export(buf, &size, 1, sizeof(uint8_t), 0, 0, key->iq);
	write_Length(der, size);
	for(i = 0; i < size; i++)
		write_8(der, buf[i]);

	free(buf);
	return 0;
}
int write_RSAPublicKey(uint8_t * der, RSAPrivateKey * key) {
	uint8_t *buf;
	unsigned long size;
	int i;

	buf = (uint8_t *) calloc(sizeof(uint8_t), mpz_sizeof(key->n));

	if(buf == NULL) {
		fprintf(stderr, "Heap exhausted !!\n");
		exit(ENOSPC);
	}

	mpz_export(buf, &size, 1, sizeof(uint8_t), 0, 0, key->n);
	write_Length(der, size);
	for(i = 0; i < size; i++)
		write_8(der, buf[i]);

	buf =
	    (uint8_t *) realloc(buf, sizeof(uint8_t) * mpz_sizeof(key->e));
	mpz_export(buf, &size, 1, sizeof(uint8_t), 0, 0, key->e);
	write_Length(der, size);
	for(i = 0; i < size; i++)
		write_8(der, buf[i]);
	free(buf);
	return 0;
}

int RSAPublicKey_to_DER(char *filepath, RSAPrivateKey * key) {
	int fd;
	uint8_t *der;
	uint16_t size_key, size_total = 0;

	fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if(fd == -1) {
		fprintf(stderr, "%s :", filepath);
		perror(NULL);
		exit(errno);
	}
	size_key = mpz_sizeof(key->n);
	size_total += size_key;
	size_total += 3;
	if(size_key < 256)
		size_total += 3 + 6;
	else
		size_total += 4 + 6;
	der = (uint8_t *) calloc(sizeof(uint8_t), size_total + 4);

	if(der == NULL) {
		fprintf(stderr, "Heap exhausted !!\n");
		exit(ENOSPC);
	}

	write_16(der, 0x3082);
	write_16(der, size_total);

	write_16(der, 0x0201);
	write_8(der, 0x00);

	write_RSAPublicKey(der, key);
	write(fd, der, size_total + 4);
	close(fd);
	return 0;
}

int RSAPrivateKey_to_DER(char *filepath, RSAPrivateKey * key) {
	int fd;
	uint8_t *der;
	uint16_t size_prime, size_total = 0;

	fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if(fd == -1) {
		fprintf(stderr, "%s :", filepath);
		perror(NULL);
		exit(errno);
	}
	size_prime = mpz_sizeof(key->p);
	size_total = 9 * size_prime;
	size_total += 3;
	if(size_prime < 128)
		size_total += 8 * 3 + 3;
	else if(size_prime == 128)
		size_total += 6 * 3 + 2 * 4 + 3;
	else
		size_total += 7 * 4 + 3 + 3;

	der = (uint8_t *) calloc(sizeof(uint8_t), size_total + 4);

	if(der == NULL) {
		fprintf(stderr, "Heap exhausted !!\n");
		exit(ENOSPC);
	}

	write_16(der, 0x3082);
	write_16(der, size_total);

	write_16(der, 0x0201);
	write_8(der, 0x00);

	write_RSAPrivateKey(der, key);
	write(fd, der, size_total + 4);
	close(fd);
	return 0;
}

int DER_to_RSAPrivateKey(char *filepath, RSAPrivateKey * key) {
	int fd, length, buf, i;
	uint8_t *value;

	fd = open(filepath, O_RDONLY);
	if(fd == -1) {
		fprintf(stderr, "%s :", filepath);
		perror(NULL);
		exit(errno);
	}
	buf = read_16(fd);
	if(buf == 0x3081)
		key->size = read_8(fd);
	else if(buf == 0x3082)
		key->size = read_16(fd);
	else {
		fprintf(stderr,"Illegal or Corrupt key\n");
		exit(1);
	}
	buf = read_16(fd);
	if(buf != 0x0201)
		return -1;
	key->version = buf = read_8(fd);
	if(buf != 0x00)

		return -1;

	length = getSizeAsUInt(fd);
	value = (uint8_t *) calloc(sizeof(int), length);

	if(value == NULL) {
		fprintf(stderr, "Heap exhausted !!\n");
		exit(ENOSPC);
	}

	for(i = 0; i < length; i++)
		value[i] = read_8(fd);
	mpz_import(key->n, length, 1, sizeof(uint8_t), 0, 0, value);

	length = getSizeAsUInt(fd);
	value = (uint8_t *) realloc(value, length);
	for(i = 0; i < length; i++)
		value[i] = read_8(fd);
	mpz_import(key->e, length, 1, sizeof(uint8_t), 0, 0, value);

	length = getSizeAsUInt(fd);
	value = (uint8_t *) realloc(value, length);
	for(i = 0; i < length; i++)
		value[i] = read_8(fd);
	mpz_import(key->d, length, 1, sizeof(uint8_t), 0, 0, value);

	length = getSizeAsUInt(fd);
	value = (uint8_t *) realloc(value, length);
	for(i = 0; i < length; i++)
		value[i] = read_8(fd);
	mpz_import(key->p, length, 1, sizeof(uint8_t), 0, 0, value);

	length = getSizeAsUInt(fd);
	value = (uint8_t *) realloc(value, length);
	for(i = 0; i < length; i++)
		value[i] = read_8(fd);
	mpz_import(key->q, length, 1, sizeof(uint8_t), 0, 0, value);

	length = getSizeAsUInt(fd);
	value = (uint8_t *) realloc(value, length);
	for(i = 0; i < length; i++)
		value[i] = read_8(fd);
	mpz_import(key->dp, length, 1, sizeof(uint8_t), 0, 0, value);

	length = getSizeAsUInt(fd);
	value = (uint8_t *) realloc(value, length);
	for(i = 0; i < length; i++)
		value[i] = read_8(fd);
	mpz_import(key->dq, length, 1, sizeof(uint8_t), 0, 0, value);

	length = getSizeAsUInt(fd);
	value = (uint8_t *) realloc(value, length);
	for(i = 0; i < length; i++)
		value[i] = read_8(fd);
	mpz_import(key->iq, length, 1, sizeof(uint8_t), 0, 0, value);

	free(value);
	close(fd);
	return 0;
}
int DER_to_RSAPublicKey(char *filepath, RSAPrivateKey * key) {
	int fd, length, buf, i;
	uint8_t *value;

	fd = open(filepath, O_RDONLY);
	if(fd == -1) {
		fprintf(stderr, "%s :", filepath);
		perror(NULL);
		exit(errno);
	}
	buf = read_16(fd);
	if(buf == 0x3081)
		key->size = read_8(fd);
	else if(buf == 0x3082)
		key->size = read_16(fd);
	else {
		fprintf(stderr,"Illegal or Corrput key\n");
		exit(1);
	}
	buf = read_16(fd);
	if(buf != 0x0201)
		return -1;
	key->version = buf = read_8(fd);
	if(buf != 0x00)
		buf = read_16(fd);

	length = getSizeAsUInt(fd);
	value = (uint8_t *) calloc(sizeof(int), length);

	if(value == NULL) {
		fprintf(stderr, "Heap exhausted !!\n");
		exit(ENOSPC);
	}

	for(i = 0; i < length; i++)
		value[i] = read_8(fd);
	mpz_import(key->n, length, 1, sizeof(uint8_t), 0, 0, value);

	length = getSizeAsUInt(fd);
	value = (uint8_t *) realloc(value, length);
	for(i = 0; i < length; i++)
		value[i] = read_8(fd);
	mpz_import(key->e, length, 1, sizeof(uint8_t), 0, 0, value);
	close(fd);
	return 0;
}


int RSAPrivateKey_to_RSAPublicKey(char *infile, char *outfile) {
	RSAPrivateKey key;
	RSAPrivateKey_init(&key);
	DER_to_RSAPrivateKey(infile, &key);
	RSAPublicKey_to_DER(outfile, &key);
	RSAPrivateKey_clear(&key);
	return 0;
}

uint8_t read_8(int fd) {
	uint8_t i = 0;
	if(read(fd, &i, 1) == 0)
		return -1;
	return i;
}

uint16_t read_16(int fd) {
	uint16_t i = 0;
	((uint8_t *) & i)[1] = read_8(fd);
	((uint8_t *) & i)[0] = read_8(fd);
	return i;
}

int write_8(uint8_t * der, uint8_t ui) {
	static int i = 0;
	der[i] = ui;
	i++;
	//write(fd, &ui, sizeof(ui));
	return 0;
}

int write_16(uint8_t * der, uint16_t ui) {
	write_8(der, ((uint8_t *) & ui)[1]);
	write_8(der, ((uint8_t *) & ui)[0]);
	return 0;
}
