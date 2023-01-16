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
#include "pkcs.h"
#include "sha2.h"


void (*hash)(const unsigned char *, unsigned int, unsigned char *);
void stp(int sha2_ndx) {
    switch (sha2_ndx) {
        case SHA224 :
            hash = sha224;
            break;
        case SHA256 :
            hash = sha256;
            break;
        case SHA384 :
            hash = sha384;
            break;
        case SHA512 :
            hash = sha512;
            break;
        case SHA512_224 :
            hash = sha512_224;
            break;
        case SHA512_256 :
            hash = sha512_256;
            break;
        default:
            exit(1);
    }
}

size_t shaLen(int ndx) {
    switch (ndx) {
        case SHA224:
            return SHA224_DIGEST_SIZE;
        case SHA256:
            return SHA256_DIGEST_SIZE;
        case SHA384:
            return SHA384_DIGEST_SIZE;
        case SHA512:
            return SHA512_DIGEST_SIZE;
        case SHA512_224:
            return SHA224_DIGEST_SIZE;
        case SHA512_256:
            return SHA256_DIGEST_SIZE;
        default:
            return 0;
    }
}

//mask generation function 함수
unsigned char *mask_generation_function(const void *seed, size_t sLen, unsigned char *mask, size_t mLen, int sha2_ndx) {
    size_t hLen;
    uint32_t counter, i, tmp_i;
    stp(sha2_ndx);
    hLen = shaLen(sha2_ndx);
    //Step 1. If mask Len > 2^32 hLen, output "mask too long" and stop.
    if (mLen > 0x100000000*hLen) {
        return NULL;
    }

    unsigned char *tmp; // mgf + C 부분을 잡고있을 tmp 포인터
    if ((tmp = (unsigned char *)malloc(sLen + 4)) == NULL) {
        return NULL;
    }
    memcpy(tmp, seed, sLen);
    // Step 3. For counter from 0 to ceil(maskLen / hLen)-1, do the following :

    counter = mLen/hLen + (mLen%hLen ? 1 : 0);

    //Step 2. Let T be the empty octet string.
    //Step 2와 3의 선언 순서가 바뀜 -> counter의 size를 알아야 malloc을 할 수 있기 때문
    unsigned char *T; // 포인터로 함 (나중에 연산할 때 전체 옮기는 것보다 포인터만 주고받는게 빠르기 때문)
    if ((T = (unsigned char *)malloc(counter * hLen)) == NULL) {
        return NULL;
    }

    // Step 3.
    // A. Convert counter to an octet string C of length 4 octets
    // B. Concatenate the hash of the seed mgfSeed and C to the octet string T:
    for (i = 0; i < counter; ++i) {
        //위의 tmp의 malloc에서 sLen + 4였던 이유, 3.B에서 Hash(mgfSeed || C)를 해야하기 때문에 지금 mgfSeed || C를 한거임.
        //hash를 수행한 후 T뒤에(T + i*hLen 만큼 떨어진 곳에) 계속 붙인다.
        tmp_i = i;
        tmp[sLen+3] = tmp_i & 0xff;
        tmp_i = tmp_i >> 8;
        tmp[sLen+2] = tmp_i & 0xff;
        tmp_i = tmp_i >> 8;
        tmp[sLen+1] = tmp_i & 0xff;
        tmp_i = tmp_i >> 8;
        tmp[sLen] = tmp_i & 0xff;

        //Hash함수 실행
        (*hash)(tmp, sLen+4, T+i*hLen);
    }
    memcpy(mask, T, mLen);
    free(tmp);
    free(T);

    return mask;
}

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
 * rsaes_oaep_encrypt() - RSA encrytion with the EME-OAEP encoding method
 * 길이가 len 바이트인 메시지 m을 공개키 (e,n)으로 암호화한 결과를 c에 저장한다.
 * label은 데이터를 식별하기 위한 라벨 문자열로 NULL을 입력하여 생략할 수 있다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. c의 크기는 RSAKEYSIZE와 같아야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_encrypt(const void *m, size_t mLen, const void *label, const void *e, const void *n, void *c, int sha2_ndx)
{
    size_t hLen, i;
    size_t k = (RSAKEYSIZE>>3) + (RSAKEYSIZE%8 ? 1 : 0);
    hLen = shaLen(sha2_ndx);

    // 메모리 할당
    unsigned char *DB = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *dbMask = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *maskedDB = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *lHash = (unsigned char *)malloc(hLen);
    unsigned char *seed = (unsigned char *)malloc(hLen);
    unsigned char *seedMask = (unsigned char *)malloc(hLen);
    unsigned char *maskedSeed = (unsigned char *)malloc(hLen);

    stp(sha2_ndx);

    if (strlen(label) > ((unsigned long long)1<<61) - 1) return PKCS_LABEL_TOO_LONG;

    if (mLen > k - 2*hLen - 2) return PKCS_MSG_TOO_LONG;

    // A. If the label L is not provided, let L be the empty string. Let lHash = Hash(L), an octet string of length hLen.
    if (label == NULL) label = "";
    (*hash)(label, strlen(label), lHash);

    // B. Generate a padding string PS consisting of k - mLen - 2hLen - 2 zero octets. The length of PS may be zero.
    // C. Concatenate lHash, PS, a single octet with hexadecimal value 0x01, and the message M to form a data block DB of
    //    length k - hLen - 1 octets as DB = lHash || PS || 0x01 || M.
    memcpy(DB, lHash, hLen);                             // lHash
    memset(DB + hLen, 0x00, k - mLen - 2 * hLen - 2);     // PS
    DB[k - mLen - hLen - 2] = 0x01;                                         // 0x01
    memcpy(DB + k - mLen - hLen - 1, m, mLen);           // M

    // D. Generate a random octet string seed of length hLen.
    arc4random_buf(seed, hLen);

    // E. Let dbMask = MGF(seed, k - hLen - 1).
    mask_generation_function(seed, hLen, dbMask, k - hLen - 1, sha2_ndx);

    // F. Let maskedDB = DB \xor dbMask.
    for (i = 0; i < k - hLen - 1; ++i) maskedDB[i] = DB[i] ^ dbMask[i];

    // G. Let seedMask = MGF(maskedDB, hLen).
    mask_generation_function(maskedDB, k - hLen - 1, seedMask, hLen, sha2_ndx);

    // H. Let maskedSeed = seed \xor seedMask.
    for (i = 0; i < hLen; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];

    // I. Concatenate a single octet with hexadecimal value 0x00, maskedSeed, and maskedDB to form an encoded message EM of
    //    length k octets as EM = 0x00 || maskedSeed || maskedDB.
    memset(c, 0x00, 1);
    memcpy(c + 1, maskedSeed, hLen);
    memcpy(c + 1 + hLen, maskedDB, k - hLen - 1);

    free(DB);
    free(dbMask);
    free(maskedDB);
    free(lHash);
    free(seed);
    free(seedMask);
    free(maskedSeed);

    return rsa_cipher(c, e, n);
}

/*
 * rsaes_oaep_decrypt() - RSA decrytion with the EME-OAEP encoding method
 * 암호문 c를 개인키 (d,n)을 사용하여 원본 메시지 m과 길이 len을 회복한다.
 * label과 sha2_ndx는 암호화할 때 사용한 것과 일치해야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsaes_oaep_decrypt(void *m, size_t *mLen, const void *label, const void *d, const void *n, const void *c, int sha2_ndx)
{
    size_t hLen, i;
    size_t k = (RSAKEYSIZE>>3) + (RSAKEYSIZE%8 ? 1 : 0);
    stp(sha2_ndx);
    hLen = shaLen(sha2_ndx);

    unsigned char *DB = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *dbMask = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *maskedDB = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *lHash = (unsigned char *)malloc(hLen);
    unsigned char *lHash2 = (unsigned char *)malloc(hLen);
    unsigned char *seed = (unsigned char *)malloc(hLen);
    unsigned char *seedMask = (unsigned char *)malloc(hLen);
    unsigned char *maskedSeed = (unsigned char *)malloc(hLen);
    unsigned char *y = (unsigned char *)malloc(1);

    // 1. length checking:
    // A. If the length of L is greater than the input limitation for the hash function (2^61 - 1 octets for SHA-1),
    //    output "decryption error" and stop.
    if (strlen(label) > ((unsigned long long)1<<61) - 1) return PKCS_LABEL_TOO_LONG;

    // B. If the length of the ciphertext C is not k octets, output "decryption error" and stop.
    // printf("length of c is %zu\n", strlen(c));
    // if (strlen(c) != k) return PKCS_INVALID_INIT;

    // C. If k < 2hLen + 2, output "decryption error" and stop.
    if (k < 2*hLen + 2) return PKCS_LABEL_TOO_LONG;

    // 2. RSA decryption:
    rsa_cipher((unsigned char *) c, d, n);

    // 3. EME-OAEP decoding:
    // A. If the label L is not provided, let L be the empty string. Let lHash = Hash(L), an octet string of length hLen
    if (label == NULL) label = "";
    (*hash)(label, strlen(label), lHash);

    // B. Separate the encoded message EM into a single octet Y, an octet string maskedSeed of length hLen, and an
    //    octet string maskedDB of length k - hLen - 1 as EM = Y || maskedSeed || maskedDB.
    memcpy(y, c, 1);
    memcpy(maskedSeed, c + 1, hLen);
    memcpy(maskedDB, c + 1 + hLen, k - hLen - 1);

    // C. Let seedMask = MGF(maskedDB, hLen).
    mask_generation_function(maskedDB, k - hLen - 1, seedMask, hLen, sha2_ndx);
    
    // D. Let seed = maskedSeed \xor seedMask.
    for (i = 0; i < hLen; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];
    
    // E. Let dbMask = MGF(seed, k - hLen - 1).
    mask_generation_function(seed, hLen, dbMask, k - hLen - 1, sha2_ndx);

    // F. Let DB = maskedDB \xor dbMask.
    for (i = 0; i < k - hLen - 1; ++i)
        DB[i] = maskedDB[i] ^ dbMask[i];

    // G. Separate DB into an octet string lHash’ of length hLen, a (possibly empty) padding string PS consisting of
    //    octets with hexadecimal value 0x00, and a message M as DB = lHash’ || PS || 0x01 || M.
    //    If there is no octet with hexadecimal value 0x01 to separate PS from M, if lHash does not equal lHash’, or
    //    if Y is nonzero, output "decryption error" and stop.
    memcpy(lHash2, DB, hLen);
    if (memcmp(lHash, lHash2, hLen) != 0) return PKCS_HASH_MISMATCH;
    for (i = hLen; i < k - hLen - 1; ++i) {
        if (DB[i] == 0x01) break;
        if (DB[i] != 0x00) return PKCS_INVALID_PS;
    }
    if (i == k - hLen - 1) return PKCS_INVALID_PS;
    if (y[0] != 0x00) return PKCS_INITIAL_NONZERO;

    // H. Let M be the message
    memcpy(m, DB + i + 1, k - hLen - 1 - i - 1);
    *mLen = k - hLen - 1 - i - 1;

    free(DB);
    free(dbMask);
    free(maskedDB);
    free(lHash);
    free(lHash2);
    free(seed);
    free(seedMask);
    free(maskedSeed);
    free(y);

    return 0;
}


/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m을 개인키 (d,n)으로 서명한 결과를 s에 저장한다.
 * s의 크기는 RSAKEYSIZE와 같아야 한다. 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s, int sha2_ndx)
{
    size_t hLen;
    size_t k = (RSAKEYSIZE>>3) + (RSAKEYSIZE%8 ? 1 : 0);
    int i;
    stp(sha2_ndx);
    hLen = shaLen(sha2_ndx);
    unsigned char *DB = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *maskedDB = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *dbMask = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *mHash = (unsigned char *)malloc(hLen);
    unsigned char *salt = (unsigned char *)malloc(hLen);
    unsigned char *mPrime = (unsigned char *)malloc(8+(2*hLen));
    unsigned char *H = (unsigned char *)malloc(hLen);

    // 1. 입력 데이터의 길이가 너무 2^64비트보다 길 때 에러 출력
    if(mLen >= 0x1000000000000000) return PKCS_MSG_OUT_OF_RANGE;

    // 2.   Let mHash = Hash(M), an octet string of length hLen.
    (*hash)(m,mLen,mHash);

    // 3.   If emLen < hLen + sLen + 2, output "encoding error" and stop.
    if((hLen<<1) + 2 > k) return PKCS_HASH_TOO_LONG;

    // 4.   Generate a random octet string salt of length sLen; if sLen = 0, then salt is the empty string.
    arc4random_buf(salt, hLen); // sLen = hLen

    // 5.   Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    //      M' is an octet string of length 8 + hLen + sLen with eight initial zero octets.
    memset(mPrime,0x00,8);
    memcpy(mPrime + 8,mHash,hLen);
    memcpy(mPrime + 8 + hLen,salt,hLen);

    // 6.   Let H = Hash(M'), an octet string of length hLen.
    (*hash)(mPrime, 8 + (hLen<<1), H);

    //step 7. //
    memset(DB,0x00,k - hLen - 1);

    //step 8.
    memset(DB + k - (hLen<<1) - 2, 0x01, 1);
    memcpy(DB + k - (hLen<<1) - 1, salt, hLen);

    //step 9. //
    mask_generation_function(H, hLen, dbMask, k - hLen - 1, sha2_ndx);

    //step 10. //
    for(i = 0; i < k - hLen - 1; ++i) maskedDB[i] = DB[i] ^ dbMask[i];

    //step 11. //
    if (maskedDB[0] >> 7 & 1) maskedDB[0] = maskedDB[0] & 0x7f;

    //step 12.
    memcpy(s, maskedDB, k - hLen - 1);
    memcpy(s + k - hLen - 1, H, hLen);
    memset(s + k - 1, 0xbc, 1);

    free(DB);
    free(maskedDB);
    free(dbMask);
    free(mHash);
    free(salt);
    free(mPrime);
    free(H);

    return rsa_cipher(s, d, n);
}

/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 * 길이가 len 바이트인 메시지 m에 대한 서명이 s가 맞는지 공개키 (e,n)으로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s, int sha2_ndx)
{
    size_t hLen;
    size_t k = (RSAKEYSIZE>>3) + (RSAKEYSIZE%8 ? 1 : 0);
    int i;
    stp(sha2_ndx);
    hLen = shaLen(sha2_ndx);
    unsigned char *mHash = (unsigned char *)malloc(hLen);
    unsigned char *H = (unsigned char *)malloc(hLen);
    unsigned char *maskedDB = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *dbMask = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *DB = (unsigned char *)malloc(k - hLen - 1);
    unsigned char *salt = (unsigned char *)malloc(hLen);
    unsigned char *M_prime = (unsigned char *)malloc(hLen+hLen+8);
    unsigned char *H_prime = (unsigned char *)malloc(hLen);

    //step 1.
    if(mLen >= 0x1000000000000000) return PKCS_MSG_TOO_LONG;

    if (rsa_cipher((unsigned char *) s, e, n)) return PKCS_MSG_OUT_OF_RANGE;

    //step 2.
    (*hash)(m, mLen, mHash);

    //step 3.
    if (k < (hLen<<1) + 2) return PKCS_MSG_TOO_LONG;

    //step 4.
    if (((unsigned char *)s)[k-1] != 0xbc) return PKCS_INVALID_LAST;

    //step 5.
    memcpy(maskedDB, s, k - hLen - 1);
    memcpy(H, s + k - hLen - 1, hLen);

    //step 6.
    if (((unsigned char *)s)[0] >> 7 == 1) return PKCS_INVALID_INIT;

    //step 7.
    mask_generation_function(H, hLen, dbMask, k - hLen - 1, sha2_ndx);

    //step 8.
    for(i = 1; i < k - hLen -1; ++i) DB[i] = maskedDB[i] ^ dbMask[i];
    DB[0] = 0x00;

    //step 10.
    for(i = 0; i < k - (hLen<<1) - 2; ++i) {
        if (DB[i] != 0x00) return PKCS_INVALID_PD2;
    }
    if (DB[k -(hLen<<1) -2] != 0x01) return PKCS_INVALID_PD2;

    //step 11.
    memcpy(salt, DB + k - (hLen<<1) - 1, hLen);

    //step 12.
    memset(M_prime, 0x00, 8);
    memcpy(M_prime + 8, mHash, hLen);
    memcpy(M_prime + 8+hLen, salt, hLen);

    //step 13.
    (*hash)(M_prime, 8 + (hLen<<1), H_prime);

    //step 14.
    for(i = 0;i < hLen; ++i) {
        if (H[i] != H_prime[i]) return PKCS_HASH_MISMATCH;
    }

    free(DB);
    free(maskedDB);
    free(dbMask);
    free(mHash);
    free(salt);
    free(M_prime);
    free(H_prime);
    free(H);

    return 0;
}

