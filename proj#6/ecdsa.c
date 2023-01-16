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
#include "ecdsa.h"
#include "sha2.h"
#include <gmp.h>
#include <string.h>


unsigned char *p=NULL;
unsigned char *n=NULL;
ecdsa_p256_t *G=NULL;

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


/*
 * Initialize 256 bit ECDSA parameters
 * 시스템파라미터 p, n, G의 공간을 할당하고 값을 초기화한다.
 */
void ecdsa_p256_init(void)
{
    unsigned char tmp_p[32]={0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    unsigned char tmp_n[32]={0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
    unsigned char tmp1[32] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
    unsigned char tmp2[32]  = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
    p = (unsigned char *)malloc(32);
    n = (unsigned char *)malloc(32);
    G = (ecdsa_p256_t *)malloc(sizeof(ecdsa_p256_t));
    ecdsa_p256_t tmp_G;
    memcpy(p, tmp_p, 32);
    memcpy(n, tmp_n, 32);
    memcpy(tmp_G.x, tmp1, 32);
    memcpy(tmp_G.y, tmp2, 32);
    memcpy(G, &tmp_G, sizeof(ecdsa_p256_t));
}

/*
 * Clear 256 bit ECDSA parameters
 * 할당된 파라미터 공간을 반납한다.
 */
void ecdsa_p256_clear(void)
{
    free(p);
    free(n);
    free(G);
}

void double_point(ecdsa_p256_t *sum, const ecdsa_p256_t *point)
{
    mpz_t x, y, lambda, x3, y3, _p, tmp;
    mpz_inits(x, y, lambda, x3, y3, _p, tmp, NULL);
    mpz_import(x, ECDSA_P256>>3, 1, 1, 1, 0, ((ecdsa_p256_t *)point)->x);
    mpz_import(y, ECDSA_P256>>3, 1, 1, 1, 0, ((ecdsa_p256_t *)point)->y);
    mpz_import(_p, ECDSA_P256>>3, 1, 1, 1, 0, p);

    // 1. lambda = (3x^2 - 3) / 2y
    mpz_pow_ui(lambda, x, 2);
    mpz_mul_ui(lambda, lambda, 3);
    mpz_sub_ui(lambda, lambda, 3);
    mpz_mul_ui(tmp, y, 2);
    mpz_invert(tmp, tmp, _p);
    mpz_mul(lambda, lambda, tmp);
    mpz_mod(lambda, lambda, _p);

    // 2. x3 = lambda^2 - 2x
    mpz_pow_ui(x3, lambda, 2);
    mpz_mul_ui(tmp, x, 2);
    mpz_sub(x3, x3, tmp);
    mpz_mod(x3, x3, _p);

    // 3. y3 = lambda(x-x3) - y
    mpz_sub(tmp, x, x3);
    mpz_mul(y3, lambda, tmp);
    mpz_sub(y3, y3, y);
    mpz_mod(y3, y3, _p);

    mpz_export(((ecdsa_p256_t *)sum)->x, NULL, 1, 1, 1, 0, x3);
    mpz_export(((ecdsa_p256_t *)sum)->y, NULL, 1, 1, 1, 0, y3);
    mpz_clears(x, y, lambda, x3, y3, _p, tmp, NULL);
}

void ecdsa_p256_add(ecdsa_p256_t *sum, const ecdsa_p256_t *point1, const ecdsa_p256_t *point2)
{
    mpz_t x1, y1, x2, y2, lambda, x3, y3, _p, tmp;
    mpz_inits(x1, y1, x2, y2, lambda, x3, y3, _p, tmp, NULL);
    mpz_import(x1, ECDSA_P256>>3, 1, 1, 1, 0, ((ecdsa_p256_t *)point1)->x);
    mpz_import(y1, ECDSA_P256>>3, 1, 1, 1, 0, ((ecdsa_p256_t *)point1)->y);
    mpz_import(x2, ECDSA_P256>>3, 1, 1, 1, 0, ((ecdsa_p256_t *)point2)->x);
    mpz_import(y2, ECDSA_P256>>3, 1, 1, 1, 0, ((ecdsa_p256_t *)point2)->y);
    mpz_import(_p, ECDSA_P256>>3, 1, 1, 1, 0, p);

    // if point1 == point2
    if (mpz_cmp(x1, x2) == 0 && mpz_cmp(y1, y2) == 0) {
        // 1. lambda = (3x^2 - 3) / 2y
        double_point(sum, point1);
    } else {
        // 2. lambda = (y2 - y1) / (x2 - x1)
        mpz_sub(lambda, y2, y1);
        mpz_sub(tmp, x2, x1);
        mpz_invert(tmp, tmp, _p);
        mpz_mul(lambda, lambda, tmp);
        mpz_mod(lambda, lambda, _p);

        // 3. x3 = lambda^2 - x1 - x2
        mpz_pow_ui(x3, lambda, 2);
        mpz_sub(x3, x3, x1);
        mpz_sub(x3, x3, x2);
        mpz_mod(x3, x3, _p);

        // 4. y3 = lambda(x1 - x3) - y1
        mpz_sub(tmp, x1, x3);
        mpz_mul(y3, lambda, tmp);
        mpz_sub(y3, y3, y1);
        mpz_mod(y3, y3, _p);
    }
    mpz_export(((ecdsa_p256_t *)sum)->x, NULL, 1, 1, 1, 0, x3);
    mpz_export(((ecdsa_p256_t *)sum)->y, NULL, 1, 1, 1, 0, y3);

    mpz_clears(x1, y1, x2, y2, lambda, x3, y3, _p, tmp, NULL);
}

/*
 * ECDSA P256 point multiplication use double and add algorithm
 */
void ecdsa_p256_mul(ecdsa_p256_t *sum, const ecdsa_p256_t *point, unsigned char *scalar)
{
    // 1. Initialize
    mpz_t _p, _scalar, _x, _y, _x3, _y3, _tmp, _point;
    mpz_inits(_p, _scalar, _x, _y, _x3, _y3, _tmp, _point, NULL);
    mpz_import(_p, ECDSA_P256>>3, 1, 1, 1, 0, p);
    mpz_import(_scalar, ECDSA_P256>>3, 1, 1, 1, 0, scalar);
    mpz_import(_x, ECDSA_P256>>3, 1, 1, 1, 0, ((ecdsa_p256_t *)point)->x);
    mpz_import(_y, ECDSA_P256>>3, 1, 1, 1, 0, ((ecdsa_p256_t *)point)->y);

    ecdsa_p256_t *tmp_p;
    tmp_p = (ecdsa_p256_t *)malloc(sizeof(ecdsa_p256_t));
    memcpy(tmp_p, point, sizeof(ecdsa_p256_t));

    unsigned char *tmp_scalar;
    tmp_scalar = (unsigned char *)malloc(ECDSA_P256>>3);
    memcpy(tmp_scalar, scalar, ECDSA_P256>>3);

    // 2. double and add
    while (mpz_cmp_ui(_scalar, 0) > 0) {
        if (mpz_tstbit(_scalar, 0) == 1) {
            ecdsa_p256_add(sum, sum, tmp_p);
        }
        ecdsa_p256_add(tmp_p, tmp_p, tmp_p);
        mpz_fdiv_q_2exp(_scalar, _scalar, 1);
    }
    mpz_clears(_p, _scalar, _x, _y, _x3, _y3, _tmp, _point, NULL);
}

/*
 * ecdsa_p256_key() - generates Q = dG
 * 사용자의 개인키와 공개키를 무작위로 생성한다.
 */
void ecdsa_p256_key(void *d, ecdsa_p256_t *Q)
{
    mpz_t d_tmp, _n;
    gmp_randstate_t state;

    mpz_inits(d_tmp, _n, NULL);
    mpz_import(_n, 32, 1, 1, 0, 0, n);

    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());

    mpz_urandomm(d_tmp, state, _n);
    // _n보다 1작은 랜덤 숫자 중 1개를 d_tmp에 넣음

    mpz_export(d, NULL, 1, 1, 1, 0, d_tmp);

    ecdsa_p256_mul(Q, G, d);

    mpz_clear(d_tmp);
}

/*
 * ecdsa_p256_sign(msg, len, d, r, s) - ECDSA Signature Generation
 * 길이가 len 바이트인 메시지 m을 개인키 d로 서명한 결과를 r, s에 저장한다.
 * sha2_ndx는 사용할 SHA-2 해시함수 색인 값으로 SHA224, SHA256, SHA384, SHA512,
 * SHA512_224, SHA512_256 중에서 선택한다. r과 s의 길이는 256비트이어야 한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_sign(const void *msg, size_t len, const void *d, void *_r, void *_s, int sha2_ndx)
{
    stp(sha2_ndx);
    mpz_t _d, _n, _k, _x, _y, mpz_r, mpz_s, _e, _tmp, _tmp2;
    mpz_inits(_d, _n, _k, _x, _y, mpz_r, mpz_s, _e, _tmp, _tmp2, NULL);
    mpz_import(_d, ECDSA_P256>>3, 1, 1, 1, 0, d);
    mpz_import(_n, ECDSA_P256>>3, 1, 1, 1, 0, n);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());

    unsigned char *e = (unsigned char *)malloc(ECDSA_P256>>3);
    unsigned char *k = (unsigned char *)malloc(ECDSA_P256>>3);

    ecdsa_p256_t *R;
    R = (ecdsa_p256_t *)malloc(sizeof(ecdsa_p256_t));

    // 1. e = hash(msg)
    (*hash)(msg, len, e);
    mpz_import(_e, ECDSA_P256>>3, 1, 1, 1, 0, e);

    // 2. 𝑒의 길이가 𝑛의 길이(256비트)보다 길면 뒷 부분은 자른다. 𝑏𝑖𝑡𝑙𝑒𝑛(𝑒) ≤ 𝑏𝑖𝑡𝑙𝑒𝑛(𝑛)
    if (mpz_sizeinbase(_e, 2) > ECDSA_P256) {
        mpz_fdiv_q_2exp(_e, _e, mpz_sizeinbase(_e, 2) - ECDSA_P256);
    }

    do {
        // 3. k = random number (0 < k < n)
        mpz_urandomm(_k, state, _n);
        mpz_export(k, NULL, 1, 1, 1, 0, _k);

        // 4. (x1, y1) = kG
        ecdsa_p256_mul(R, G, k);
        mpz_import(_x, ECDSA_P256>>3, 1, 1, 1, 0, R->x);
        mpz_import(_y, ECDSA_P256>>3, 1, 1, 1, 0, R->y);

        // 5. r = x1 mod n. if r = 0, go to 3
        mpz_mod(mpz_r, _x, _n);

        // 6. s = (k^-1)(e + dr) mod n. if s = 0, go to 3
        mpz_invert(_tmp, _k, _n);
        mpz_mul(mpz_s, _d, mpz_r);
        mpz_add(mpz_s, _e, mpz_s);
        mpz_mul(mpz_s, _tmp, mpz_s);
        mpz_mod(mpz_s, mpz_s, _n);
    } while(mpz_cmp_ui(mpz_r, 0) == 0 || mpz_cmp_ui(mpz_s, 0) == 0);

    mpz_export(_r, NULL, 1, 1, 1, 0, mpz_r);
    mpz_export(_s, NULL, 1, 1, 1, 0, mpz_s);
    mpz_clears(_n, _d, mpz_r, mpz_s, _k, _x, _y, _tmp, NULL);
    return 0;
}

/*
 * ecdsa_p256_verify(msg, len, Q, r, s) - ECDSA signature veryfication
 * It returns 0 if valid, nonzero otherwise.
 * 길이가 len 바이트인 메시지 m에 대한 서명이 (r,s)가 맞는지 공개키 Q로 검증한다.
 * 성공하면 0, 그렇지 않으면 오류 코드를 넘겨준다.
 */
int ecdsa_p256_verify(const void *msg, size_t len, const ecdsa_p256_t *_Q, const void *_r, const void *_s, int sha2_ndx)
{
    stp(sha2_ndx);
    mpz_t tmp_r, tmp_s, _n, _e, inv_s, u1, u2, tmp_x;
    unsigned char *e = (unsigned char *)malloc(256);
    mpz_inits(tmp_r, tmp_s, _n, _e, inv_s, u1, u2, tmp_x, NULL);
    mpz_import(tmp_r, 32, 1, 1, 1, 0, _r);
    mpz_import(tmp_s, 32, 1, 1, 1, 0, _s);
    mpz_import(_n, ECDSA_P256 >> 3, 1, 1, 1, 0, n);

    // 1. check 0 < r < n, 0 < s < n
    if (mpz_cmp_ui(tmp_r, 0) <= 0 || mpz_cmp(tmp_r, _n) >= 0 || mpz_cmp_ui(tmp_s, 0) <= 0 || mpz_cmp(tmp_s, _n) >= 0) {
        return -1;
    }

    // 2. e = H(msg)
    (*hash)(msg, len, e);
    mpz_import(_e, 32, 1, 1, 0, 0, e);

    // 3. If the length of 𝑒 is longer than the length of 𝑛 (256 bits), cut the back. bitlen(e) <= bitlen(n)
    if (mpz_sizeinbase(_e, 2) > ECDSA_P256) mpz_tdiv_r_2exp(_e, _e, ECDSA_P256);

    // 4. 𝑢1 = 𝑒𝑠−1 mod 𝑛, 𝑢2 = 𝑟 𝑠−1 mod 𝑛.
    mpz_invert(inv_s, tmp_s, _n); mpz_mul(u1, _e, inv_s); mpz_mod(u1, u1, _n);
    mpz_mul(u2, tmp_r, inv_s); mpz_mod(u2, u2, _n);

    unsigned char *tmp_u1 = (unsigned char *)malloc(256);
    unsigned char *tmp_u2 = (unsigned char *)malloc(256);
    mpz_export(tmp_u1, NULL, 1, 1, 1, 0, u1);
    mpz_export(tmp_u2, NULL, 1, 1, 1, 0, u2);

    // 5. (x1, y1) = u1G + u2Q
    ecdsa_p256_t *tmp = (ecdsa_p256_t *)malloc(sizeof(ecdsa_p256_t));
    ecdsa_p256_mul(tmp, G, tmp_u1);
    ecdsa_p256_t *tmp2 = (ecdsa_p256_t *)malloc(sizeof(ecdsa_p256_t));
    ecdsa_p256_mul(tmp2, _Q, tmp_u2);
    ecdsa_p256_add(tmp, tmp, tmp2);

    // 6. if 𝑟 ≡ 𝑥1 (mod 𝑛), then valid, otherwise invalid
    mpz_import(tmp_x, ECDSA_P256 >> 3, 1, 1, 1, 0, tmp->x);
    mpz_mod(tmp_x, tmp_x, _n);
    if (mpz_cmp(tmp_x, tmp_r) == 0) return 0;
    else return -1;
}
