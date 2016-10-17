#include "include.h"
int main(int argc, char **argv) {
	int bits = 1024;
	char c;
	char outfile[256] = "rsa_private_key.der";
	char *infile;
	char *help="Usage: ./genrsa [OPTION]... [FILE]...\n\
Generate RSA private key Compatible with OpenSSL.\n\
No options are mandatory\n\
    -b n [1024]                   Generate a RSA key of 'n' bits.'n' has to a multiple of 256.\n\
    -o outfile [rsa_key.der]      Write the RSA private key to DER format in outfile.\n\
    -p infile                     Generate public key from the private key infile.\n\
\n";

	RSAPrivateKey key;
	RSAPrivateKey_init(&key);

	while((c = getopt(argc, argv, "hb:o:p:")) != -1) {
		switch (c) {
		case 'b':
			bits = atoi(optarg);
			break;
		case 'o':
			strcpy(outfile,optarg);
			break;
		case 'h':
			printf("%s",help);
			break;
		case 'p':
			infile = optarg;			
			break;
		case '?':
			printf("Unknown option character `\\x%x'.\n",
			       optopt);
			return 1;
		default:
			abort();
		}
	}
	if(!strstr(outfile,".der")){
		strcat(outfile,".der");
	}
	printf("Generating %d bits RSA Private key......\n",bits);

	if(generate_RSAPrivateKey(&key, bits))
		return errno;
	RSAPrivateKey_to_DER(outfile, &key);

	printf("%d bits RSA Private key generated and written to %s\n",bits,outfile);

	return 0;
}
