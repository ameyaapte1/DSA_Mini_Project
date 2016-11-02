/*
 *	RSA key Geberation : Main code for generation of RSA keys
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
#include "base64.h"

int main(int argc, char **argv) {
	int bits = 1024;
	int public_key = 0;
	int type = 0;
	char c;
	char private_outfile[256] = "rsa_private_key";
	char public_outfile[256] = "rsa_public_key";
	char *infile;
	char *help = "Usage: ./genrsa [OPTION]... [FILE]...\n\
Generate RSA private key Compatible with OpenSSL.\n\
No options are mandatory\n\
    -b n [1024]                   Generate a RSA key of 'n' bits.'n' has to a multiple of 256.\n\
    -o outfile [rsa_private_key.der]      Write the RSA private key to DER format in outfile.\n\
    -p infile                     Generate public key from the private key infile.\n\
    -d Output DER file		  Default output is PEM files\n";

	RSAPrivateKey key;
	RSAPrivateKey_init(&key);

	while((c = getopt(argc, argv, "hb:o:p:d")) != -1) {	/*Parse the arguments sepecified */
		switch (c) {
		case 'b':
			bits = atoi(optarg);
			break;
		case 'o':
			strcpy(private_outfile, optarg);
			strcpy(public_outfile, optarg);
			break;
		case 'h':
			printf("%s", help);
			exit(0);
			break;
		case 'p':
			public_key = 1;
			infile = optarg;
			break;
		case 'd':
			type = 1;
			break;
		case '?':
			printf("Unknown option character `\\x%x'.\n",
			       optopt);
			return 1;
		default:
			abort();
		}
	}
	if(!strstr(public_outfile, ".der")) 
		strcat(public_outfile, ".der");

	if(type == 1 && !strstr(private_outfile, ".der")) 
		strcat(private_outfile, ".der");

	if(type == 0 && !strstr(private_outfile, ".pem")) 
		strcat(private_outfile, ".pem");	

	if(public_key == 0 && type == 0) {
		printf("Generating %d bits RSA Private key......\n", bits);

		if(generate_RSAPrivateKey(&key, bits))
			return errno;
		RSAPrivateKey_to_PEM(private_outfile, &key);

		printf("%d bits RSA Private key generated and written to %s\n", bits, private_outfile);
	} else if(public_key == 0 && type == 1) {
		printf("Generating %d bits RSA Private key......\n", bits);

		if(generate_RSAPrivateKey(&key, bits))
			return errno;
		RSAPrivateKey_to_DER(private_outfile, &key);

		printf("%d bits RSA Private key generated and written to %s\n",bits, private_outfile);


	} else {
		printf("Extracting RSA Public key from Private key ......\n");

		RSAPrivateKey_to_RSAPublicKey(infile, type, public_outfile);

		printf("RSA Public key generated and written to %s\n",public_outfile);
	}

	return 0;
}
