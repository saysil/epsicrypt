
/*
 * Free key pairs
 *
 *
 *
 *
 *
 *
 */

#include "rsa_keys.h"

void rsa_freekeypair(struct RsaPublic  *pubkey, 
                     struct RsaPrivate *privkey) 
{
	mpz_clear(pubkey->mod);
	mpz_clear(pubkey->exp);
	
	mpz_clear(privkey->mod);
	mpz_clear(privkey->exp);
	mpz_clear(privkey->d);
	mpz_clear(privkey->p);
	mpz_clear(privkey->q);
	mpz_clear(privkey->u);
}



