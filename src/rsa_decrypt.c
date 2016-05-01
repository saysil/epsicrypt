
/*
 * RSA decryption 
 *
 *
 *
 *
 *
 *
 */

#include "rsa_keys.h"
#include "rsa_codes.h"

#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <limits.h>

#include "rsa_extrafuncs.h"

int rsa_decrypt(mpz_t                  *num, 
                const struct RsaPrivate privkey, 
                const int               bitnum,
                FILE                   *fp) 
{
	if (bitnum%8 || bitnum <= 0) {
		return BITS_NOT_8;
	} //Do a little checking, decrypting can be hazardous
	
	if (!num) {
		return MSGLONG_ERR;
	}
	
	if (mpz_sgn(*num) <= 0) {
		return NEGATIVE_ERR;
	}
	
	if (mpz_sizeinbase(*num, 2) > (unsigned)bitnum*2 || mpz_sizeinbase(*num, 2) <= (unsigned)(bitnum)) {
		return MSGLONG_ERR;
	}
	
    int n  = bitnum*2-128; //the padding can't be as big as the RSA modulus
	int k0 = n>>2;
    //printf("\n\n%d\n\n", k0);
    #define k1 k0

	unsigned char tp[sizeof(int)];
	unsigned char tp2[bitnum/CHAR_BIT];
	
	mpz_t r;
	mpz_init(r);
	
	mpz_t u;
	mpz_init(u);
	
	fread(tp, 1, sizeof(int), fp);
	
    mpzfrombuf(&r, tp, sizeof(int)-1);
	
    mpz_add_ui(r, r, 1);
	
	mpz_pow_ui(u, r, mpz_get_ui(privkey.exp)); //To prevent timing attacks
	mpz_mul(*num, u, *num);
	mpz_powm(*num, *num, privkey.d, privkey.mod);
	mpz_divexact(*num, *num, r); //actual decryption here
	
    //gmp_printf("After Encrypt: \n%ZX\n\n", *num);

	unsigned char tp3[bitnum/CHAR_BIT];
	
	//set X & Y
	
	mpz_t x, y, m;
	mpz_init(x);
	mpz_init(y);
	mpz_init(m);
	
	for (int i=0; i<bitnum+k1; i++) {
		(mpz_tstbit(*num, i+k0)) ? mpz_setbit(x, i) : mpz_clrbit(x, i);
	}
    //gmp_printf("\nX: %ZX\n", x);
	
	for (int i=0; i<k0; i++) {
		(mpz_tstbit(*num, i)) ? mpz_setbit(y, i) : mpz_clrbit(y, i);
	}
	//gmp_printf("Y: %ZX\n", y);
    //gmp_printf("\nR: %ZX\n\n", r);
	/*********** Hash Function H ***********/
	mpz_set_ui(r, 0);
	mpz_t h;
	mpz_init(h);
	
	hashmpz(&h, x, k0/CHAR_BIT);
	
	mpz_xor(r, h, y);
	
	/*********** Hash Function H ***********/
	/*********** Hash Function G ***********/
	mpz_t g;
	mpz_init(g);
	
	hashmpz(&g, r, (bitnum+k1)/CHAR_BIT);
	
	mpz_xor(m, g, x); //Here, M is both m and k1
	
	/*********** Hash Function G ***********/
		
   /**Check if X is properly padded       **
	** If it's not, generate a random     **
	** make it *look* valid, so it will   **
	** fail later, mitigating ACC attacks **/
	
	char padtamp = 0;
    
    //gmp_printf("%ZX\n", m);

	if (mpz_sizeinbase(m, 2) > (bitnum+k1)) { 
        //trigger immediately if the size of our message is bigger than the specified padding
		fread(tp2, 1, bitnum/CHAR_BIT, fp);
        printf("k1 + bitnum > m\n");
        mpzfrombuf(&m, tp2, bitnum/CHAR_BIT);

		padtamp = 1;
	}
	
	for (int i=0; i<k1; i++) {
		if (mpz_tstbit(m, i)) { 
            //incorrectly padded
            //Triggers if we have any non-zero bits in the padding area
			padtamp = 1;
			for (int i=0; i<k1+bitnum+k0; i++) {
				mpz_clrbit(m, i); //make it look correctly padded
			}
			fread(tp3, 1, bitnum/CHAR_BIT, fp);

            mpzfrombuf(&m, tp3, bitnum/CHAR_BIT);
			break;
		}
	}

	mpz_set_ui(*num, 0);
	
	for (int i=0; i<bitnum; i++) {
		(mpz_tstbit(m, i+k1)) ? mpz_setbit(*num, i) : mpz_clrbit(*num, i);
	} //set our number back properly

	mpz_clear(r);
	mpz_clear(u);
	mpz_clear(h);
	mpz_clear(y);
	mpz_clear(x);
	mpz_clear(g);
	mpz_clear(m);
	if (padtamp) {
		return 1;
	}
	return 0;
}

