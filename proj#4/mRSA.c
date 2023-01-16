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
#include "mRSA.h"

/*
 * mod_add() - computes a + b mod m
 */
static uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
{
    a = a % m;
    b = b % m;
    return (a >= m - b) ? a - (m - b) : (a + b);
}

/*
 * mod_mul() - computes a * b mod m
 */
static uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r = 0;

    while (b > 0) {
        if (b & 1)  r = mod_add(r, a, m);
        b = b >> 1;
        a = mod_add(a, a, m);
    }

    return r;
}

/*
 * mod_pow() - computes a^b mod m
 */
static uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r = 1;

    while (b > 0) {
        if (b & 1)  r = mod_mul(r, a, m);
        b = b >> 1;
        a = mod_mul(a, a, m);
    }

    return r;
}

/*
 * gcd() - Euclidean algorithm
 */
static uint64_t gcd(uint64_t a, uint64_t b)
{
    uint64_t m;

    while (b != 0) {     // b == 0일 때, 나누어 떨어진 경우이므로 a가 최대공약수가 된다.
        m = a % b;
        a = b;
        b = m;
    }
    return a;
}

/*
 * mul_inv() - computes multiplicative inverse a^-1 mod m
 * It returns 0 if no inverse exist.
 */
static uint64_t mul_inv(uint64_t a, uint64_t m)
{
    uint64_t d0 = a, d1 = m;
    uint64_t x0 = 1, x1  = 0, q, tmp;

    while (d1 > 1) {
        q = d0 / d1;
        tmp = d0 - q * d1; d0 = d1; d1 = tmp;
        tmp = x0 - q * x1; x0 = x1; x1 = tmp;
    }

    if (d1 == 1)                                // d1 = 1일 경우
        return ((x1>>63) == 0 ? x1 : x1+m);     // 첫 번째 비트를 통해 부호를 확인하고 x1이 음수라면 m을 더한다.
    else                                        // 역이 존재하지 않는 경우
        return 0;
}

/*
 * Miller-Rabin Primality Testing against small sets of bases
 *
 * if n < 2^64,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37.
 *
 * if n < 3317044064679887385961981,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, and 41.
 */
static const uint64_t a[BASELEN] = {2,3,5,7,11,13,17,19,23,29,31,37};

/*
 * miller_rabin() - Miller-Rabin Primality Test (deterministic version)
 *
 * n > 3, an odd integer to be tested for primality
 * It returns 1 if n is prime, 0 otherwise.
 */
static int miller_rabin(uint64_t n)
{
    if ((n % 2 == 0 && n != 2) || n == 1) return COMPOSITE;

    int k = 0;
    bool flag;
    uint64_t q = n-1;
    uint64_t tmp;

    while ((q % 2) == 0){
        q /= 2;
        k++;
    }

    for (int i = 0; i < BASELEN && a[i] < n-1; i++){
        tmp = mod_pow(a[i], q, n);

        if (tmp == 1) {   // INCONCLUSIVE
            continue;   // a[i]에 대해 소수임을 확인
        }

        flag = true;
        for (int j = 0; j < k; j++){
            if (mod_pow(tmp, 1 << j, n) == n - 1) {   // INCONCLUSIVE
                flag = false;
                break;
            }
        }
        if (flag) return COMPOSITE;
    }
    return PRIME;
}

/*
 * mRSA_generate_key() - generates mini RSA keys e, d and n
 *
 * Carmichael's totient function Lambda(n) is used.
 */
void mRSA_generate_key(uint64_t *e, uint64_t *d, uint64_t *n)
{
    uint64_t p = 0, q = 0;
    uint64_t lambda_n;

    while (p * q < MINIMUM_N) { // p, q 랜덤 선택
        while (true) {  // 소수 p 생성
            arc4random_buf(&p, sizeof(uint32_t));
            if (miller_rabin(p)) break;
        }
        while (true) {  // 소수 q 생성
            arc4random_buf(&q, sizeof(uint32_t));
            if (miller_rabin(q)) break;
        }
    }
    *n = p * q; // n 생성
    lambda_n = (p-1) * (q-1) / gcd(p-1,q-1);  // lambda(n)

    while (true) { // e, d 생성
        arc4random_buf(e,sizeof(uint64_t)); // random number e
        if ((1 < *e) && (*e < lambda_n) && (gcd(*e,lambda_n) == 1)) {
            *d = mul_inv(*e,lambda_n);
            break;
        }
    }
}

/*
 * mRSA_cipher() - compute m^k mod n
 *
 * If data >= n then returns 1 (error), otherwise 0 (success).
 */
int mRSA_cipher(uint64_t *m, uint64_t k, uint64_t n)
{
    if (*m >= n) return 1;      // 오류 발생

    *m = mod_pow(*m, k, n);  // compute m^k mod n

    return 0;                   // 정상
}