#include "include.h"

int main(int argc, char *argv[]) {

	char message[20] = "ameya";
	char *key_file, *out_file, *in_file, *buf;
	int ifd, ofd, key_size,encdec_flag;
	uint16_t i;
	char c;

	RSABlock block;
	RSAPrivateKey key;
	RSAPrivateKey_init(&key);

	while((c = getopt(argc, argv, "edi:k:o:")) != -1) {
		switch (c) {
		case 'e':
			encdec_flag = 1;
			break;
		case 'd':
			encdec_flag = 0;
			break;
		case 'k':
			key_file = optarg;
			break;
		case 'o':
			out_file = optarg;
			break;
		case 'i':
			in_file = optarg;
			break;
		case '?':
			//printf("Unknown option character %c.\n",optopt);
			return 1;
		default:
			abort();
		}
	}
	/*
	ifd = open(in_file, O_RDONLY);

	if(ifd == -1) {
		fprintf(stderr, "%s :", in_file);
		perror(NULL);
		exit(errno);
	}

	ofd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if(ifd == -1) {
		fprintf(stderr, "%s :", out_file);
		perror(NULL);
		exit(errno);
	}*/
	/*if(encdec_flag == 1) {
		DER_to_RSAPrivateKey(key_file, &key);
		key_size = mpz_sizeof(key.n);
		buf = (char *) malloc(key_size * sizeof(char));
		while((i = read(ifd, buf, key_size - 12))) {
			buf[i] = '\0';
			RSA_Encrypt(buf, &block, &key);
			write(out_file,&(block.length),sizeof(unsigned int));
			write(out_file,block.data,&(block.length));
		}
	}*/
	DER_to_RSAPrivateKey(key_file, &key);
	RSA_Encrypt(message,&block,&key);
	RSA_Decrypt(&block, message, &key);
	printf("\n%s\n", message);
	RSAPrivateKey_clear(&key);
	return 0;
}
