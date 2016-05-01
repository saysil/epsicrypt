
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
#include <limits.h>

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
	
	int n = bitsize*2-128; //we have to have less bits than the rsa modulus
	
	if (mpz_sizeinbase(*num, 2) > (unsigned)bitsize) {
		return MSGLONG_ERR;
	}
	
	int k0;
	
	mpz_t m;
	mpz_t r;
	
	mpz_t g;
	mpz_t h;
	
	mpz_t x;
	mpz_t y;
	
	k0 = n>>2;
    //printf("\n\n%d\n\n", k0);
	#define k1 k0
	
	unsigned char tp[k0/CHAR_BIT];
	
	mpz_init(m);
	mpz_init(r);
	
	for (int i=0; i<bitsize; i++) {
		(mpz_tstbit(*num, i)) ? mpz_setbit(m, i + k1) : mpz_clrbit(m, i+k1);
	} //set m to the 'new' encrytion message
    
    for (int i=0; i<k1; i++) {
        mpz_clrbit(m, i);
    } //zero out k1
	
	fread(tp, sizeof(char), k0/CHAR_BIT, fp);

	mpzfrombuf(&r, tp, k0/CHAR_BIT);
    //set r to a random k0 bit string ??? WHY DID I WRITE THIS

    //gmp_printf("\nBefore Padding\n%ZX\n", m);

    //printf("N-k0 = %d\nSize = %d\n", bitsize*2-k0, mpz_sizeinbase(m, 2));
	
    //gmp_printf("\nR: %ZX\n\n", r);

	/*********** Hash Function G ***********/
	mpz_init(g);
	mpz_init(x);
	
	if (hashmpz(&g, r, (bitsize+k1)/CHAR_BIT)) {
		return HASH_ERR;
	}  //set g2 to our new hash
	
    //printf("Size of m: %d\nSize of g: %d\n", mpz_sizeinbase(m,2), mpz_sizeinbase(g,2));
	mpz_xor(x, m, g); //xor the two values to give us x
	//gmp_printf("\nX: %ZX\n\n", x);
	/*********** Hash Function G ***********/
	/*********** Hash Function H ***********/
	mpz_init(h);
	mpz_init(y);
	
	if (hashmpz(&h, x, k0/CHAR_BIT)) {
		return HASH_ERR;
	} //set h2 to our new hash of k0 bits
	
	mpz_xor(y, r, h);
    //gmp_printf("Y: %ZX\n", y);
	/*********** Hash Function H ***********/
	
    mpz_set_ui(*num, 0);
	//concatenate the new numbers x and y
	for (int i=0; i<k0; i++) {
		(mpz_tstbit(y, i)) ? mpz_setbit(*num, i) : mpz_clrbit(*num, i);
	}
	
	for (int i=0; i<(bitsize+k1); i++) {
		(mpz_tstbit(x, i)) ? mpz_setbit(*num, i+k0) : mpz_clrbit(*num, i+k0);
	}

    //printf("X = %d\nN-k0 = %d\nX+Y = %d\n", mpz_sizeinbase(x, 2), n-k0, mpz_sizeinbase(x, 2) + mpz_sizeinbase(y, 2));
    
    //printf("Size of message: %d\n", mpz_sizeinbase(*num, 2));

    //gmp_printf("Before Encrypt: \n%ZX\n\n", *num);

	//Encrypt the data with padding, as C = m^e mod n
	mpz_powm(*num, *num, pubkey.exp, pubkey.mod);
	
    //gmp_printf("Finished: \n%ZX\nSize: %d\n", *num, mpz_sizeinbase(*num, 2)/CHAR_BIT);
	//close and free all our memory
	
	mpz_clear(m);
	mpz_clear(r);
	mpz_clear(x);
	mpz_clear(y);
	mpz_clear(g);
	mpz_clear(h);
	return 0;
}


