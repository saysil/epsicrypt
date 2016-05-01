
/*
 * File to Mpz Array
 *
 *
 *
 *
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include "rsa.h"
#include "rsa_extrafuncs.h"

mpz_t *filtompz(FILE                *opt,
                const unsigned int   nummpz,
                const unsigned int   bytenum)
{

    mpz_t *mpzarr  = malloc(sizeof(mpz_t)*nummpz);
    char  *tmpread = malloc(sizeof(char )*bytenum);
       
    int aread;
    for (int i=0; i<nummpz; i++) {
        memset(tmpread, 0, bytenum); //zero out memory
        aread = fread(tmpread, sizeof(char), bytenum, opt); //The glorious fread doesnt care if we hit EOF. Hooray!

        if (i != nummpz-1 && aread != bytenum) { //error reading
            return NULL;
        }

        mpz_init(mpzarr[i]);
        
        printf("%.*s", bytenum, tmpread);
        printf("\n%d\n", aread);
        
        mpzfrombuf(&mpzarr[i], tmpread, bytenum);
        //buffrommpz(&mpzarr[i], tmpread, bytenum);
        
        //gmp_printf("%ZX\n", mpzarr[i]);
        //printf("%.*s\n", bytenum, tmpread);
    }
    
    free(tmpread);
    return mpzarr;
}

