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


#include <stdio.h>
#include "include.h"
#include "base64.h"

void PEM_to_RSAPrivateKey(char *filepath, RSAPrivateKey * key) {
	FILE *fp_pem, *fp_der;
	char *der_file;
	char buf;
	int i=0;
	unsigned char *base64;
	size_t fsize, base64_len;

	fp_pem = fopen(filepath, "r");
	fp_der = fopen("temp.der", "w");

	if(fp_der == NULL || fp_pem == NULL) {
		fprintf(stderr, "%s :", filepath);
		perror(NULL);
		exit(errno);
	}


	fseek(fp_pem, 0, SEEK_END);
	fsize = ftell(fp_pem);
	fseek(fp_pem, 0, SEEK_SET);  

	der_file = (char *) malloc(fsize);

	fread(der_file, 32, 1, fp_pem);
	der_file[32] = '\0';
	if(strcmp(der_file,"-----BEGIN RSA PRIVATE KEY-----\n") != 0){
		fprintf(stderr, "Illegal or Corrupt key\n");
		exit(1);
	}

	while(1){
		fread(&buf, 1, 1, fp_pem);
		if(buf == '-')
			break;
		else if (buf != '\n'){
			der_file[i++] = buf;
		}
	}

	base64 = base64_decode(der_file,i,&base64_len);
	fwrite(base64, base64_len, 1, fp_der);

	free(der_file);
	fclose(fp_der);
	fclose(fp_pem);

	DER_to_RSAPrivateKey("temp.der",key);

	remove("temp.der");

}

void RSAPrivateKey_to_PEM(char *filepath, RSAPrivateKey * key) {
	char *begin_rsa ="-----BEGIN RSA PRIVATE KEY-----\n";
	char *end_rsa ="\n-----END RSA PRIVATE KEY-----\n";
	FILE *fp_der, *fp_pem;
	size_t fsize;
	unsigned char *der_file;
	char *base64;

	RSAPrivateKey_to_DER("temp.der", key);

	fp_pem = fopen(filepath, "w");
	fp_der = fopen("temp.der", "r");

	if(fp_der == NULL || fp_pem == NULL) {
		fprintf(stderr, "%s :", filepath);
		perror(NULL);
		exit(errno);
	}

	fprintf(fp_pem,"%s",begin_rsa);

	fseek(fp_der, 0, SEEK_END);
	fsize = ftell(fp_der);
	fseek(fp_der, 0, SEEK_SET);  
	der_file = malloc(fsize);

	fread(der_file, fsize, 1, fp_der);
	base64 = base64_encode(der_file,fsize);
	
	fprintf(fp_pem,"%s",base64);
	fprintf(fp_pem,"%s",end_rsa);

	free(base64);
	free(der_file);

	remove("temp.der");
}
