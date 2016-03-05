
/*
 * Encryption Handler
 *
 *
 *
 *
 *
 *
 */

#include "rsa_codes.h"
#include "rsa_keys.h"

#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>

#include "rsa_extrafuncs.h"

int rsa_encrypt(mpz_t                 *num, 
                const struct RsaPublic pubkey, 
                const int              bitsize,
                FILE                  *fp) 
{
    if (pubkey.version != VERSION_NO) {
        return VERSION_ERR;
    }

	if (bitsize%8) {
		return BITS_NOT_8;
	}
	
	/*do our input checks*/
	
	if (mpz_sgn(*num) < 0) {
		return NEGATIVE_ERR;
	}
	
	int n = (bitsize-32)*2;
	
	if (mpz_sizeinbase(*num, 2) >= (unsigned)n>>1) {
		return MSGLONG_ERR;
	}
	
	int k0;
	
	mpz_t m;
	mpz_t r;
	
	mpz_t g;
	mpz_t h;
	
	mpz_t x;
	mpz_t y;
	
	k0 = bitsize>>2;
	#define k1 k0
	
	unsigned char tp[k0/8+1];
	
	mpz_init(m);
	mpz_init(r);
	
	for (int i=0; i<bitsize; i++) {
		(mpz_tstbit(*num, i)) ? mpz_setbit(m, i + k1) : mpz_clrbit(m, i+k1);
	} //set m to the 'new' encrytion message
	
	fread(tp, sizeof(char), k0/8+1, fp);
	   
    used += k0/8+1;

	int j=0;
	for (int i=0; i<k1; i++) {
		j+=(i%8 == 0 && i!=0);
		(1&tp[j]>>i%8) ? mpz_setbit(r, i) : mpz_clrbit(r, i);
	} //set r to a random k1 bit string
	
	/*********** Hash Function G ***********/
	mpz_init(g);
	mpz_init(x);
	
	if (hashmpz(&g, r, (n-k0)/8)) {
		return HASH_ERR;
	}  //set g2 to our new hash
	
	mpz_xor(x, m, g); //xor the two values to give us x
	
	/*********** Hash Function G ***********/
	/*********** Hash Function H ***********/
	mpz_init(h);
	mpz_init(y);
	
	if (hashmpz(&h, x, k0/8)) {
		return HASH_ERR;
	} //set h2 to our new hash of k0 bits
	
	mpz_xor(y, r, h);
	/*********** Hash Function H ***********/
	
	//concatenate the new numbers x and y
	for (int i=0; i<k0; i++) {
		(mpz_tstbit(y, i)) ? mpz_setbit(*num, i) : mpz_clrbit(*num, i);
	}
	
	for (int i=0; i<(n-k0); i++) {
		(mpz_tstbit(x, i)) ? mpz_setbit(*num, i+k0) : mpz_clrbit(*num, i+k0);
	}
	
	//Encrypt the data with padding, as C = m^e mod n
	mpz_powm(*num, *num, pubkey.exp, pubkey.mod);
	
	//close and free all our memory
	
	mpz_clear(m);
	mpz_clear(r);
	mpz_clear(x);
	mpz_clear(y);
	mpz_clear(g);
	mpz_clear(h);
	return 0;
}


