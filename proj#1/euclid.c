/*
 * Copyright 2020-2022. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었다.
 */
#include "euclid.h"

/*
 * gcd() - Euclidean algorithm
 *
 * 유클리드 알고리즘 gcd(a,b) = gcd(b,a mod b)를 사용하여 최대공약수를 계산한다.
 * 만일 a가 0이면 b가 최대공약수가 된다. 그 반대도 마찬가지이다.
 * a, b가 모두 음이 아닌 정수라고 가정한다.
 * 재귀함수 호출을 사용하지 말고 while 루프를 사용하여 구현하는 것이 빠르고 좋다.
 */
int gcd(int a, int b)
{
    int m;

    while (b != 0) {     // b == 0일 때, 나누어 떨어진 경우이므로 a가 최대공약수가 된다.
        m = a % b;
        a = b;
        b = m;
    }
    return a;
}

/*
 * xgcd() - Extended Euclidean algorithm
 *
 * 확장유클리드 알고리즘은 두 수의 최대공약수 gcd(a,b) = ax + by 식을
 * 만족하는 x와 y를 계산하는 알고리즘이다. 강의노트를 참조하여 구현한다.
 * a, b가 모두 음이 아닌 정수라고 가정한다.
 */
int xgcd(int a, int b, int *x, int *y)
{
    int d0 = a, d1 = b;
    int x0 = 1, x1 = 0;
    int y0 = 0, y1 = 1, q, tmp;
    while (d1 > 0) {    // gcd(a, b) = d0 = a * x + b * y을 만족하는 x과 y이 존재한다.
        q = d0 / d1;
        d0 = d0 - q * d1;
        tmp = d0; d0 = d1; d1 = tmp;    // SWAP(d0, d1)
        x0 = x0 - q * x1;
        tmp = x0; x0 = x1; x1 = tmp;    // SWAP(x0, x1)
        y0 = y0 - q * y1;
        tmp = y0; y0 = y1; y1 = tmp;    // SWAP(y0, y1)
    }
    *x = x0;
    *y = y0;

    return d0;
}

/*
 * mul_inv() - computes multiplicative inverse a^-1 mod m
 *
 * 모듈로 m에서 a의 곱의 역인 a^-1 mod m을 구한다.
 * 만일 역이 존재하지 않으면 0을 리턴한다.
 * 확장유클리드 알고리즘을 변형하여 구현한다. 강의노트를 참조한다.
 */
int mul_inv(int a, int m)
{
    int d0 = a, d1 = m;
    int x0 = 1, x1 = 0, q, tmp;

    while (d1 > 1) {     // gcd(a, b) = d = ax + by 인 x와 y가 존재한다.
        q = d0 / d1;
        tmp = d0 - q * d1; d0 = d1; d1 = tmp;
        tmp = x0 - q * x1; x0 = x1; x1 = tmp;
    }

    if (d1 == 1)
        return (x1 > 0 ? x1 : x1 + m);
    else
        return 0;
}

/*
 * umul_inv() - computes multiplicative inverse a^-1 mod m
 *
 * 입력이 unsigned 64 비트 정수일 때 모듈로 m에서 a의 곱의 역인 a^-1 mod m을 구한다.
 * 만일 역이 존재하지 않으면 0을 리턴한다. 확장유클리드 알고리즘을 변형하여 구현한다.
 * 입출력 모두가 unsigned 64 비트 정수임에 주의한다.
 */
uint64_t umul_inv(uint64_t a, uint64_t m)
{
    uint64_t d0 = a, d1 = m;
    uint64_t x0 = 1, x1  = 0, q, tmp;

    while (d1 > 1) {        // unsigned 즉, 64 비트 정수에서 mul_inv와 같은 방식을 사용하여 a^-1 mod m을 구할 수 있다.
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
 * gf16_mul(a, b) - a * b mod x^16+x^5+x^3+x+1
 *
 * 15차식 다항식 a와 b를 곱하고 결과를 16차식 x^16+x^5+x^3+x+1로 나눈 나머지를 계산한다.
 * x^16 = x^5+x^3+x+1 (mod x^16+x^5+x^3+x+1) 특성을 이용한다.
 */
uint16_t gf16_mul(uint16_t a, uint16_t b)
{
    uint16_t r = 0;
    while (b > 0) {
        if (b & 1) r = r ^ a;                           // 존재하는 차수항일 경우 r과 a 를 XOR 연산한다.
        b = b >> 1;                                     // b를 한 자리씩 비트연산으로 당긴다.
        a = ((a << 1) ^ ((a >> 15) & 1 ? 0x2B : 0));    // x^5+x^3+x+1의 계수를 16진수로 표현하면, 0x2B이다.
    }
    return r;
}

/*
 * gf16_pow(a,b) - a^b mod x^16+x^5+x^3+x+1
 *
 * 15차식 다항식 a를 b번 지수승한 결과를 16차식 x^16+x^5+x^3+x+1로 나눈 나머지를 계산한다.
 * gf16_mul()과 "Square Multiplication" 알고리즘을 사용하여 구현한다.
 */
uint16_t gf16_pow(uint16_t a, uint16_t b)
{
    uint16_t r = 1;
    while (b > 0) {
        if (b & 1)
            r = gf16_mul(r, a);
        b = b >> 1;
        a = gf16_mul(a,a);
    }
    return r;
}

/*
 * gf16_inv(a) - a^-1 mod x^16+x^5+x^3+x+1
 *
 * 모둘러 x^16+x^5+x^3+x+1에서 a의 역을 구한다.
 * 역을 구하는 가장 효율적인 방법은 다항식 확장유클리드 알고리즘을 사용하는 것이다.
 * 다만 여기서는 복잡성을 피하기 위해 느리지만 알기 쉬운 지수를 사용하여 구현하였다.
 */
uint16_t gf16_inv(uint16_t a)
{
    return gf16_pow(a, 0xfffe);
}
