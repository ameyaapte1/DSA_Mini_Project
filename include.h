#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>


#include <gmp.h>


#define DEBUG 0
#define spad "abcd"
#define epad "dcba"
#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

typedef struct RSAPrivateKey {
	unsigned short int size, version,key_type;
	mpz_t p, q, n, d, e, dp, dq, iq;
} RSAPrivateKey;

typedef  struct RSABlock {
	char *data;
	unsigned int data_length,msg_length;
} RSABlock;


unsigned int mpz_sizeof(const mpz_t num);

void RSAPrivateKey_init(RSAPrivateKey * key);
void RSAPrivateKey_clear(RSAPrivateKey * key);
uint8_t read_8(int fd);
uint16_t read_16(int fd);

int write_8(uint8_t * der, uint8_t ui);
int write_16(uint8_t * der, uint16_t ui);

int write_Length(uint8_t * der, unsigned long size);
int write_RSAPrivateKey(uint8_t * der, RSAPrivateKey * key);
int write_RSAPublicKey(uint8_t * der, RSAPrivateKey * key);

int write_block(int fd, RSABlock *block) ;
int read_block(int fd, RSABlock *block) ;

int RSAPrivateKey_to_DER(char *filepath, RSAPrivateKey * key);
int DER_to_RSAPrivateKey(char *filepath, RSAPrivateKey * key);
int RSAPublicKey_to_DER(char *filepath, RSAPrivateKey * key);
int DER_to_RSAPublicKey(char *filepath, RSAPrivateKey * key);

int RSAPrivateKey_to_RSAPublicKey(char *infile, char *outfile);

int getrand(mpz_t x, int bits);
int generate_RSAPrivateKey(RSAPrivateKey * key, int bits);


int RSA_Encrypt(char *message,unsigned int len, RSABlock *block, RSAPrivateKey * key);
int RSA_Decrypt(RSABlock *block, char *message, RSAPrivateKey * key);

