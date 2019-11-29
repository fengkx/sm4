#include <stdio.h>
#include <stdlib.h>
#include "sm4.h"

sm4_ctx ctx;
uint8_t gkey[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

int main(int argc, char *argv[]) {
	
	if(argc < 2) {
		fprintf(stderr, "should provide a file path\n");
		exit(1);
	}
	//FILE *fp = fopen(argv[1], "rb");
	//FILE *fp_out = fopen("out.enc", "w+");
	//if(fp == 0) {
	//	perror("fopen");
	//	exit(1);
	//}
	sm4_set_key(gkey, &ctx);
	//sm4_cbc_encrypt_file(fp, fp_out, &ctx);
	//fclose(fp);
	//fclose(fp_out);

#ifdef DEBUG
	printf("BEGIN DECRYPT ------------- BEGIN DECRYPT\n");
#endif
	FILE *fp_decrypt_in = fopen("out.enc", "rb");
	FILE *fp_decrypt_out = fopen("out.dec", "w+");

	sm4_cbc_decrypt_file(fp_decrypt_in, fp_decrypt_out, &ctx);

	fclose(fp_decrypt_in);
	fclose(fp_decrypt_out);
}
