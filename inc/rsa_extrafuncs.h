
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

int setlargeprime(FILE  *restrict fp,
                  mpz_t *restrict p,
                  unsigned short  bitcount);

void mpzfrombuf(mpz_t *restrict opt,
                void  *restrict buf,
                int             size);
void buffrommpz(mpz_t *restrict opt,
                void  *restrict buf,
                int             size);

#endif

