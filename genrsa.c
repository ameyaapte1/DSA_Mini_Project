#include "include.h"
int main(int argc, char **argv) {
	int bits = 1024;
	char *outfile="rsa_key.der";

	char c;
	RSAPrivateKey key;
	RSAPrivateKey_init(&key);

	while((c = getopt(argc, argv, "b:o:")) != -1) {
		switch (c) {
		case 'b':
			bits = atoi(optarg);
			break;
		case 'o':
			outfile=optarg;
			break;
		case '?':
			printf("Unknown option character `\\x%x'.\n",
			       optopt);
			return 1;
		default:
			abort();
		}
	}
	if(generate_RSAPrivateKey(&key, bits))
		return errno;
	RSAPrivateKey_to_DER(outfile, &key);	
	return 0;
}
