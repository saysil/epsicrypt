/*
 * 
 *  Naive RSA-OAEP Implementation
 * 
 *  COPYRIGHT 2015 (c) Droodomis
 * 
 *  droodomis@gmail.com
 * 
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>
#include <openssl/evp.h>
#include <limits.h>

#include "rsa_codes.h"
#include "rsa_keys.h"

void rsa_freeKeyPair(struct RsaPublic  *pubkey, 
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

int hashmpz(mpz_t       *r, 
            mpz_t        h, 
            unsigned int length) 
{ //takes length in bytes
	char *tempstore = malloc(mpz_sizeinbase(h, 16)+2);
	memset(tempstore, 0, mpz_sizeinbase(h, 16)+2);
	
	mpz_set_ui(*r, 0);
	
    char *buffer;

	unsigned char *string = malloc(length+1);
	memset(string, 0, length+1);
	
	buffer = mpz_get_str(tempstore, 16, h);

                             /*mpz_sizeinbase returns the size, a null terminator, and a minus sign*/
	if (!PKCS5_PBKDF2_HMAC(buffer, mpz_sizeinbase(h, 16)+2, NULL, 0, PBKDF_ITERATIONS, EVP_sha512(), length, string)) {
		return HASH_ERR;
	}

	for (int i=0; i<length; i++) {
		for (int j=0; j<CHAR_BIT; j++) {
			(1 & (string[i]>>j)) ? mpz_setbit(*r, i*CHAR_BIT+j) : mpz_clrbit(*r, i*CHAR_BIT+j); 
            //Loop through and set all the bits in our hash
		}
	}

	free(string);
	free(tempstore);
	return 0;
}

int setlargeprime(FILE          *fp, 
                  mpz_t         *p, 
                  unsigned short bitcount) 
{
	unsigned char tp[bitcount/CHAR_BIT]; //temp p
	fread(tp, sizeof(char), bitcount/CHAR_BIT, fp); //fill the buffer with random bytes
	
	for (int i=0; i<bitcount/CHAR_BIT; i++) {
		for (int j=0; j<CHAR_BIT; j++) {
			(1 & tp[i] >> j) ? mpz_setbit(*p, i*CHAR_BIT+j) : mpz_clrbit(*p, i*CHAR_BIT+j); //set bits for p
		}
	}
	if (!mpz_tstbit(*p, 0)) {
		mpz_setbit(*p, 0);
	}
	while (!mpz_probab_prime_p(*p, (40*(bitcount*2/1000+1)))) {
		mpz_add_ui(*p, *p, 2); //run rabin miller
	}
	return 0;
}

/****** TODO: Signing and Verification ******/

