
/*
 * Extra functions for RSA
 *
 *
 *
 *
 *
 *
 */

#ifndef RSA_EXTRAFUNCS_H
#define RSA_EXTRAFUNCS_H

#include <gmp.h>

int hashmpz(mpz_t       *r,
            mpz_t        h,
            unsigned int length);

int setlargeprime(FILE          *fp,
                  mpz_t         *p,
                  unsigned short bitcount);

#endif

