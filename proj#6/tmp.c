mpz_t _n, _d, mpz_r, mpz_s, _e, _k, _x, _y, _tmp;
mpz_inits(_n, _d, mpz_r, mpz_s, _e, _k, _x, _y, _tmp, NULL);
mpz_import(_n, ECDSA_P256>>3, 1, 1, 1, 0, n);
mpz_import(_d, ECDSA_P256>>3, 1, 1, 1, 0, d);

gmp_randstate_t state;
gmp_randinit_default(state);
gmp_randseed_ui(state, arc4random());

ecdsa_p256_t *R;
R = (ecdsa_p256_t *)malloc(sizeof(ecdsa_p256_t));

unsigned char *e = (unsigned char *)malloc(256);
unsigned char *k = (unsigned char *)malloc(256);

// 2. e = Hash(msg)
(*hash)(msg, len, e);
mpz_import(_e, 32, 1, 1, 1, 0, e);
mpz_set_str(_e, "9A9083505BC92276AEC4BE312696EF7BF3BF603F4BBD381196A029F340585312", 16);
if (mpz_sizeinbase(_e, 2) > ECDSA_P256) {
mpz_tdiv_r_2exp(_e, _e, ECDSA_P256);
}