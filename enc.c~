#include "include.h"

int main(int argc, char *argv[]) {

	char *key_file, *out_file, *in_file, *buf;
	int ifd, ofd, key_size,encdec_flag;
	uint16_t i;
	char c;

	RSABlock block;
	RSAPrivateKey key;
	RSAPrivateKey_init(&key);

	if(argc == 1) {
		fprintf(stderr,"Help will be printed here!!\n");
		return 1;
	}
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
			printf("Unknown option character %c.\n",optopt);
			return 1;
		default:
			abort();
		}
	}
	
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
	}
	if(encdec_flag == 1) {
		DER_to_RSAPublicKey(key_file, &key);
		key_size = mpz_sizeof(key.n);
		buf = (char *) calloc(sizeof(char),key_size);
		while((i = read(ifd, buf, key_size - 9))) {
			RSA_Encrypt(buf,i,&block, &key);
			printf("%d\n",i);
			write_block(ofd,&block);
		}
	}
	else{
		DER_to_RSAPrivateKey(key_file, &key);
		//gmp_printf("%Zd\n%Zd\n%Zd\n",key.n,key.d,key.e);
		key_size = mpz_sizeof(key.n);
		buf = (char *) calloc(sizeof(char),key_size);
		while(read_block(ifd,&block)) {
			i=RSA_Decrypt(&block,buf,&key);
			printf("%d\n",i);
			write(ofd,buf,i);
		}
	}
	/*DER_to_RSAPrivateKey(key_file, &key);
	RSA_Encrypt(message,&block,&key);
	RSA_Decrypt(&block, message, &key);
	printf("\n%s\n", message);
	RSAPrivateKey_clear(&key);
	*/
	free(buf);
	close(ifd);
	close(ofd);
	return 0;
}
int write_block(int fd, RSABlock *block) {
	write(fd,&(block->data_length),sizeof(unsigned int));
	write(fd,&(block->msg_length),sizeof(unsigned int));
	return write(fd,block->data,block->data_length);
}
int read_block(int fd, RSABlock *block) {
	if(read(fd,&(block->data_length),sizeof(unsigned int))==0)
		return 0;
	read(fd,&(block->msg_length),sizeof(unsigned int));
	block->data = (char *)calloc(block->data,sizeof(char)*(block->data_length));
	read(fd,block->data,block->data_length);
	return block->data_length;
}
