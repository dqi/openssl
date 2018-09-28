#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

int main() {

	/* Generate private and public key */
	EVP_PKEY *pkey_a = NULL;
	EVP_PKEY *pkey_b = NULL;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_keygen(pctx, &pkey_a);
	EVP_PKEY_keygen(pctx, &pkey_b);

    /* Print keys to stdout */
	/* PEM_write_PrivateKey(stdout, pkey_a, NULL, NULL, 0, NULL, NULL); */
	/* PEM_write_PrivateKey(stdout, pkey_b, NULL, NULL, 0, NULL, NULL); */


	EVP_PKEY_CTX_free(pctx);

    uint64_t tmp_count1 = 0;
    uint64_t tmp_count2 = 0;
    asm volatile ( "rdtsc\n\t"
            "shl $32, %%rdx\n\t"
            "or %%rdx, %0\n\t"
            "mfence"
            : "=a" (tmp_count1)
            :
            : "rdx");
	/* Generate shared secret */
	EVP_PKEY_CTX *ctx;
	unsigned char *skey;
	size_t skeylen;
	ctx = EVP_PKEY_CTX_new(pkey_a, NULL);

	if (!ctx) {
		/* Error */
		printf("CTX is empty");
	}

	if (EVP_PKEY_derive_init(ctx) <= 0) {
		/* Error */
		printf("EVP derive initialization failed\n");
	}

	if (EVP_PKEY_derive_set_peer(ctx, pkey_b) <= 0) {
		/* Error */
		printf("EVP derive set peer failed\n");
	}

	/* Determine buffer length */
	if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
		/* Error */
		printf("EVP derive failed\n");
	}
	skey = OPENSSL_malloc(skeylen);

	if (!skey) {
		/* Malloc failure */
		printf("OpenSSL Malloc failed");
	}

	if (EVP_PKEY_derive(ctx, skey, &skeylen) <= 0) {
		/* Error */
		printf("Shared key derivation failed");
	}
    asm volatile ( "mfence\n\t"
            "rdtsc\n\t"
            "shl $32, %%rdx\n\t"
            "or %%rdx, %0"
            : "=a" (tmp_count2)
            :
            : "rdx");
    printf("x25519: %lu\n", tmp_count2 - tmp_count1);
	/* printf("\nShared secret:\n"); */

	/* for (size_t i = 0; i < skeylen; i++) { */
	/* 	printf("%02x", skey[i]); */
	/* } */

	return 0;
}
