#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main() {
    // Generate ED25519 keypair
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    uint64_t tmp_count1 = 0;
    uint64_t tmp_count2 = 0;
    asm volatile ( "rdtsc\n\t"
            "shl $32, %%rdx\n\t"
            "or %%rdx, %0\n\t"
            "mfence"
            : "=a" (tmp_count1)
            :
            : "rdx");

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    // type parameter must be NULL for ED25519 since it is PureEdDSA.
    EVP_DigestSignInit(ctx, &pctx, NULL, NULL, pkey);

    unsigned char tbs[] = "Hello world";
    unsigned char sigret[256] = {0};
    size_t siglen = 256;

    EVP_DigestSign(ctx, sigret, &siglen, tbs, sizeof(tbs));
    asm volatile ( "mfence\n\t"
            "rdtsc\n\t"
            "shl $32, %%rdx\n\t"
            "or %%rdx, %0"
            : "=a" (tmp_count2)
            :
            : "rdx");
    printf("ed25519: %lu\n", tmp_count2 - tmp_count1);

    /* printf("Siglen = %d\n", (int)siglen); // expect Siglen = 64 for ED25519 signautre */

    // free keys and contexts
    /* EVP_PKEY_CTX_free(pctx); */
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);

    return 0;
}
