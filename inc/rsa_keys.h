
/*
 *
 * Defines keys, both private and public
 *
 *
 *
 *
 *
 */

#ifndef RSA_KEYS_H
#define RSA_KEYS_H

#include <gmp.h>

struct RsaPublic {
	int version;
	mpz_t mod; //modulus
	mpz_t exp; //exponenent
};

struct RsaPrivate {
	int version;
	mpz_t mod; //pub mod
	mpz_t exp; //pub exponenet
	
	mpz_t d; //exponent; modinverse of u
	
	mpz_t p;
	mpz_t q; //primes p and q
	
	mpz_t u; //totient of n
};

#endif

