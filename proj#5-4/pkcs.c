/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었다.
 */
#ifdef __linux__
#include <bsd/stdlib.h>
#elif __APPLE__
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <gmp.h>
#include <gmpxx.h>
#include "pkcs.h"
#include "sha2.h"


void (*hash)(const unsigned char *, unsigned int, unsigned char *);


/*
 * rsa_generate_key() - generates RSA keys e, d and n in octet strings.
 * If mode = 0, then e = 65537 is used. Otherwise e will be randomly selected.
 * Carmichael's totient function Lambda(n) is used.
 */
void rsa_generate_key(void *_e, void *_d, void *_n, int mode)
{
    mpz_t p, q, lambda, e, d, n, gcd;
    gmp_randstate_t state;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(p, q, lambda, e, d, n, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    /*
     * Generate prime p and q such that 2^(RSAKEYSIZE-1) <= p*q < 2^RSAKEYSIZE
     */
    do {
        do {
            mpz_urandomb(p, state, RSAKEYSIZE/2);
            mpz_setbit(p, 0);
            mpz_setbit(p, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(p, 50) == 0);
        do {
            mpz_urandomb(q, state, RSAKEYSIZE/2);
            mpz_setbit(q, 0);
            mpz_setbit(q, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(q, 50) == 0);
        mpz_mul(n, p, q);
    } while (!mpz_tstbit(n, RSAKEYSIZE-1));
    /*
     * Generate e and d using Lambda(n)
     */
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(lambda, p, q);
    if (mode == 0)
        mpz_set_ui(e, 65537);
    else do {
        mpz_urandomb(e, state, RSAKEYSIZE);
        mpz_gcd(gcd, e, lambda);
    } while (mpz_cmp(e, lambda) >= 0 || mpz_cmp_ui(gcd, 1) != 0);
    mpz_invert(d, e, lambda);
    /*
     * Convert mpz_t values into octet strings
     */
    mpz_export(_e, NULL, 1, RSAKEYSIZE/8, 1, 0, e);
    mpz_export(_d, NULL, 1, RSAKEYSIZE/8, 1, 0, d);
    mpz_export(_n, NULL, 1, RSAKEYSIZE/8, 1, 0, n);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(p, q, lambda, e, d, n, gcd, NULL);
}

/*
 * rsa_cipher() - compute m^k mod n
 * If m >= n then returns PKCS_MSG_OUT_OF_RANGE, otherwise returns 0 for success.
 */
static int rsa_cipher(void *_m, const void *_k, const void *_n)
{
    mpz_t m, k, n;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(m, k, n, NULL);
    /*
     * Convert big-endian octets into mpz_t values
     */
    mpz_import(m, RSAKEYSIZE/8, 1, 1, 1, 0, _m);
    mpz_import(k, RSAKEYSIZE/8, 1, 1, 1, 0, _k);
    mpz_import(n, RSAKEYSIZE/8, 1, 1, 1, 0, _n);
    /*
     * Compute m^k mod n
     */
    if (mpz_cmp(m, n) >= 0) {
        mpz_clears(m, k, n, NULL);
        return PKCS_MSG_OUT_OF_RANGE;
    }
    mpz_powm(m, m, k, n);
    /*
     * Convert mpz_t m into the octet string _m
     */
    mpz_export(_m, NULL, 1, RSAKEYSIZE/8, 1, 0, m);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(m, k, n, NULL);
    return 0;
}



/*
 * Hash(int sha2_ndx) - output length in octets of hash function Hash
 * Option:
 *      sha2_ndx - hash function index
 */
int Hash(int sha2_ndx)
{
    switch (sha2_ndx) {
        case SHA224:
            hash = sha224;
            return SHA224_DIGEST_SIZE;
        case SHA256:
            hash = sha256;
            return SHA256_DIGEST_SIZE;
        case SHA384:
            hash = sha384;
            return SHA384_DIGEST_SIZE;
        case SHA512:
            hash = sha512;
            return SHA512_DIGEST_SIZE;
        case SHA512_224:
            hash = sha512_224;
            return SHA224_DIGEST_SIZE;
        case SHA512_256:
            hash = sha512_256;
            return SHA256_DIGEST_SIZE;
        default:
            return 0;
    }
}

void xor(unsigned char *a, const unsigned char *b, int len)
{
    int i;

    for (i = 0; i < len; i++)
        a[i] ^= b[i];
}


/*
 * RSAES-OAEP-ENCRYPT ((n, e), M, L)
 * Options:
 *      Hash - hash function (hLen denotes the length in octets of the hash function output)
 *      MGF mask generation function
 * Input:
 *      (n, e) - recipient’s RSA public key (k denotes the length in octets of the RSA modulus n)
 *      M - message to be encrypted, an octet string of length mLen, where mLen <= k - 2hLen - 2
 *      L optional label to be associated with the message; the default value for L, if L is not provided, is the empty string
 * Output:
 *      C ciphertext, an octet string of length k
 * Errors:
 *      "message too long"; "label too long"
 * Assumption:
 *      RSA public key (n, e) is valid
 */
int rsaes_oaep_encrypt(const void *m, size_t mLen, const void *label, const void *e, const void *n, void *c, int sha2_ndx)
{
    int hLen, k, i, j, lLen;
    uint8_t *seed, *dbMask, *seedMask, *db, *lHash, *ps;
    uint8_t *p;

    hLen = Hash(sha2_ndx);
    lLen = strlen(label);

    // 1. Length checking:
    //     a. If the length of label is greater than the input limitation for the hash function (2^61 - 1 octets for SHA-1), output "label too long" and stop.
    if (lLen > (1 << 61) - 1)
        return PKCS_MSG_TOO_LONG;

    //     b. If mLen > k - 2hLen - 2, output "message too long" and stop.
    k = RSAKEYSIZE/8;
    if (mLen > k - 2*hLen - 2)
        return PKCS_MSG_TOO_LONG;

    // 2. EME-OAEP encoding (see Figure 1 below):
    //     a. If the label L is not provided, let L be the empty string. Let lHash = Hash(L), an octet string of length hLen (see the note below).
    lHash = malloc(hLen);
    hash(label, lLen, lHash);
    //     b. Generate a padding string PS consisting of k - mLen - 2*hLen - 2 zero octets. The length of PS may be zero.
    ps = malloc(k - mLen - 2*hLen - 2);
    memset(ps, 0, k - mLen - 2*hLen - 2);
    //     c. Concatenate lHash, PS, a single octet with hexadecimal value 0x01, and the message M to form a data block DB of length k - hLen - 1 octets as
    //         DB = lHash || PS || 0x01 || M.
    db = malloc(k - hLen - 1);
    p = db;
    memcpy(p, lHash, hLen);
    p += hLen;
    memcpy(p, ps, k - mLen - 2*hLen - 2);
    p += k - mLen - 2*hLen - 2;
    *p++ = 0x01;
    memcpy(p, m, mLen);
    //     d. Generate a random octet string seed of length hLen.
    seed = malloc(hLen);
    arc4random_buf(seed, hLen);
    //     e. Let dbMask = MGF(seed, k - hLen - 1).
    dbMask = malloc(k - hLen - 1);
    mgf1(seed, hLen, dbMask, k - hLen - 1, sha2_ndx);

    //     f. Let maskedDB = DB \xor dbMask.
    for (i = 0; i < k - hLen - 1; i++)
        db[i] ^= dbMask[i];
    //     g. Let seedMask = MGF(maskedDB, hLen).

    //     h. Let maskedSeed = seed \xor seedMask.
    //     i. Concatenate a single octet with hexadecimal value 0x00, maskedSeed, and maskedDB to form an encoded message EM of length k octets as
    //         EM = 0x00 || maskedSeed || maskedDB.
}

/*
 * rsaes_oaep_decrypt() - RSA decrytion with the EME-OAEP encoding method
 * 암호문 c를 개인키 (d,n)을 사용하여 원본 메시지 m과 길이 len을 회복한다.
 * label과 sha2_ndx는 암호화할 때 사용한 것과 일치해야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_decrypt(void *m, size_t *mLen, const void *label, const void *d, const void *n, const void *c, int sha2_ndx)
{
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다.
 * s의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s, int sha2_ndx)
{
}

/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지 공개키 (e,n)으로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s, int sha2_ndx)
{
}

void sha1(size_t hLen, )

