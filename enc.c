#include "include.h"

int main(int argc, char *argv[]) {

	char *key_file, *out_file, *in_file, *buf;
	int key_size, encdec_flag;
	FILE *ifd, *ofd;
	size_t len;
	char c;
	char *help="Usage: ./enc [OPTION]... [FILE]...\n\
Encrypt/Decrypt files using RSA Public/Private keys.\n\
Mandatory option are -e/d -i infile -o outfile -k key_file\n\
    -e                    Encrypt data.\n\
    -d			  Decrypt data.\n\
    -i infile		  The file to be encrypted.\n\
    -o outfile     	  The filename of the encrypted file.\n\
    -k keyfile            RSA key file.\n\n";
	RSABlock block;
	RSAPrivateKey key;
	RSAPrivateKey_init(&key);

	if(argc < 8) {
		fprintf(stderr, "Not enough arguments\n%s",help);
		return 1;
	}
	while((c = getopt(argc, argv, "hedi:k:o:")) != -1) {
		switch (c) {
		case 'h':
			printf("%s",help);
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
		case 'o':
			out_file = optarg;
			break;
		case 'i':
			in_file = optarg;
			break;
		case '?':
			printf("Unknown option character %c.\n", optopt);
			return 1;
		default:
			abort();
		}
	}
	printf("Encrypting %s to %s using %s key......\n",in_file,out_file,key_file);

	mpz_init(block.message);
	mpz_init(block.ciphertext);

	ifd = fopen(in_file,"r");
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

	if(encdec_flag == 1) {
		fwrite("RSA ENCRYPTED",sizeof(char),14,ofd);
		DER_to_RSAPublicKey(key_file, &key);
		key_size = mpz_sizeof(key.n);
		buf = (char *) calloc(sizeof(char), key_size);

		while((len = fread(buf,1,key_size-9,ifd))) {
			RSA_Encrypt(buf, len, &block, &key);
			fwrite(&len,sizeof(size_t),1,ofd);
			mpz_out_raw(ofd,block.ciphertext);
		}
		
	} else {
		DER_to_RSAPrivateKey(key_file, &key);
		//gmp_printf("%Zd\n%Zd\n%Zd\n",key.n,key.d,key.e);
		key_size = mpz_sizeof(key.n);
		buf = (char *) calloc(sizeof(char), key_size);
		fread(buf,sizeof(char),14,ifd);
		if(strcmp(buf,"RSA ENCRYPTED") !=0 ){
			fprintf(stderr,"Illegal or corrupt encrytped file.\n");
			exit(1);
		}
		while(fread(&len,sizeof(size_t),1,ifd)) {
			mpz_inp_raw(block.ciphertext,ifd);
			RSA_Decrypt(&block, buf,len, &key);
			fwrite(buf,1,len,ofd);
		}
	}
	/*DER_to_RSAPrivateKey(key_file, &key);
	   RSA_Encrypt(message,&block,&key);
	   RSA_Decrypt(&block, message, &key);
	   printf("\n%s\n", message);
	   RSAPrivateKey_clear(&key);
	 */
	mpz_clear(block.message);
	mpz_clear(block.ciphertext);

	printf("File encrypted Successfully\n");

	free(buf);
	fclose(ifd);
	fclose(ofd);
	return 0;
}
