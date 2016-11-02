/*
 *	File Encryption using RSA : File encryption using RSA 
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

int main(int argc, char *argv[]) {

	char *key_file, *out_file, *in_file, *buf;
	int key_size, encdec_flag;
	FILE *ifd, *ofd;
	size_t len;
	char c;
	int type;
	char *help = "Usage: ./enc [OPTION]... [FILE]...\n\
Encrypt/Decrypt files using RSA Public/Private keys.\n\
Mandatory option are -e/d -t key_type -i infile -o outfile -k key_file\n\
    -e                    Encrypt data.\n\
    -d			  Decrypt data.\n\
    -i infile		  The file to be encrypted.\n\
    -o outfile     	  The filename of the encrypted file.\n\
    -k keyfile            RSA key file.\n\
    -t key_type		  RSA key type PEM or DER\n";

	RSABlock block;
	RSAPrivateKey key;
	RSAPrivateKey_init(&key);

	if(argc < 10) {
		fprintf(stderr, "Not enough arguments\n%s", help);
		return 1;
	}
	while((c = getopt(argc, argv, "hedi:k:o:t:")) != -1) {	/*Parse the available arguments */
		switch (c) {
		case 'h':
			printf("%s", help);
			break;
		case 'e':
			encdec_flag = 1;
			break;
		case 'd':
			encdec_flag = 0;
			break;
		case 'k':
			key_file = optarg;
			break;
		case 't':
			if(strcmp(optarg,"PEM") == 0) 
				type = 0;
			else if(strcmp(optarg,"DER") == 0) 
				type = 1;
			else {
				fprintf(stderr,"Unknown file format %s.\n", optarg);
				exit(1);
			}
			break;
		case 'o':
			out_file = optarg;
			break;
		case 'i':
			in_file = optarg;
			break;
		case '?':
			fprintf(stderr,"Unknown option character %c.\n", optopt);
			return 1;
		default:
			abort();
		}
	}

	mpz_init(block.message);	/*temporary BLOCK */
	mpz_init(block.ciphertext);

	ifd = fopen(in_file, "r");
	if(ifd == NULL) {
		fprintf(stderr, "%s :", in_file);
		perror(NULL);
		exit(errno);
	}

	ofd = fopen(out_file, "w");
	if(ifd == NULL) {
		fprintf(stderr, "%s :", out_file);
		perror(NULL);
		exit(errno);
	}

	type ? DER_to_RSAPublicKey(key_file, &key) : PEM_to_RSAPrivateKey(key_file, &key);
	if(encdec_flag == 1) {
		printf("Encrypting %s to %s using %s ......\n", in_file,
		       out_file, key_file);


		fwrite("RSA ENCRYPTED", sizeof(char), 14, ofd);

		key_size = mpz_sizeof(key.n);

		buf = (char *) calloc(sizeof(char), key_size);

		while((len = fread(buf, 1, key_size - 9, ifd))) {

			RSA_Encrypt(buf, len, &block, &key);
			fwrite(&len, sizeof(size_t), 1, ofd);	/*write the length of the ciphertext in the current block */
			mpz_out_raw(ofd, block.ciphertext);	/*write the mpz_int in binary form to the file */
		}
		printf("File encrypted Successfully\n");

	} else {
		printf("Decrypting %s to %s using %s ......\n", in_file,
		       out_file, key_file);

		key_size = mpz_sizeof(key.n);

		buf = (char *) calloc(sizeof(char), key_size);

		fread(buf, sizeof(char), 14, ifd);

		if(strcmp(buf, "RSA ENCRYPTED") != 0) {	/*Identifier */
			fprintf(stderr,
				"Illegal or corrupt encrytped file.\n");
			exit(1);
		}
		while(fread(&len, sizeof(size_t), 1, ifd)) {	/*read the length of ciphertext in the current block */
			mpz_inp_raw(block.ciphertext, ifd);	/*read mpz_int stored in binary form from the file */
			RSA_Decrypt(&block, buf, len, &key);
			fwrite(buf, 1, len, ofd);
		}
		printf("File decrypted Successfully\n");
	}
	mpz_clear(block.message);
	mpz_clear(block.ciphertext);


	free(buf);
	fclose(ifd);
	fclose(ofd);
	return 0;
}
