
/*
 * Generate Public and private keys
 *
 *
 *
 *
 *
 *
 */

#include <stdio.h>
#include <gmp.h>

#include "rsa_codes.h"
#include "rsa_keys.h"

#include "rsa_extrafuncs.h"

int rsa_genkeys(struct RsaPublic    *pubkey, 
                struct RsaPrivate   *privkey, 
                const unsigned short bitcount,
                FILE                *fp) 
{
	mpz_init(pubkey->mod);
	mpz_init(pubkey->exp);
	
	mpz_init(privkey->mod);
	mpz_init(privkey->exp);
	mpz_init(privkey->d);
	mpz_init(privkey->p);
	mpz_init(privkey->q);
	mpz_init(privkey->u);
	
    pubkey->version = VERSION_NO;
    privkey->version = VERSION_NO;


	if (bitcount%8) {
		return BITS_NOT_8;
	}
	
	mpz_t p, q, n, totn, tmpp, tmpq, e;
	mpz_init(p); mpz_init(q); mpz_init(n);
	
	do {
		setlargeprime(fp, &p, bitcount); //Gen P
	
		setlargeprime(fp, &q, bitcount); //Gen Q
	
		mpz_mul(n, p, q); //compute n
	
		mpz_init(totn);
		mpz_init(tmpp);
		mpz_init(tmpq);
	
		mpz_sub_ui(tmpp, p, 1);
		mpz_sub_ui(tmpq, q, 1);
		mpz_mul(totn, tmpp, tmpq); //computing the totient of n as (p-1)(q-1)
	
		mpz_init(e);
	
		mpz_set_ui(e, 65537); //generate e so that e is coprime with φ(n)
	
	} while (mpz_divisible_p(totn, e));

	mpz_set(pubkey->mod, n);
	mpz_set(privkey->mod, n);
	mpz_set(pubkey->exp, e);
	mpz_set(privkey->u, totn);
	
	mpz_set(privkey->p, p);
	mpz_set(privkey->q, q); //setting the private and public key variables
	mpz_set(privkey->exp, e);
	
	mpz_invert(privkey->d, e, totn);
	
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n);
	mpz_clear(totn);
	mpz_clear(tmpp);
	mpz_clear(tmpq);
	mpz_clear(e);
	return 0;
}

