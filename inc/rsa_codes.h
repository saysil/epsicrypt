
/*
 * Codes and errors for RSA
 *
 *
 *
 *
 *
 *
 */

#ifndef RSA_CODES_H
#define RSA_CODES_H

#include <inttypes.h>

#define BITS_NOT_8 1
#define NEGATIVE_ERR 2
#define HASH_ERR 3
#define MSGLONG_ERR 4
#define VERSION_ERR 5

static const uint32_t VERSION_NO = 2;

#ifdef PBKDF_CUSTOM
    #define PBKDF_ITERATIONS PBKDF_CUSTOM
#else
    #define PBKDF_ITERATIONS 1000000
#endif



#ifdef PBKDF_OAEP_CUSTOM
    #define PBKDF_OAEP_ITERATIONS PBKDF_OAEP_CUSTOM
#else 
    #ifdef PBKDF_OAEP_FAST
        #define PBKDF_OAEP_ITERATIONS 300000
    #else
        #define PBKDF_OAEP_ITERATIONS PBKDF_ITERATIONS
    #endif
#endif

#define PBKDF_MIN 500 /* This value is NOT to change. This is merely to negate *
                       * The extreme inprobability that we recieve 0 as our    *
                       * pbkdf value.                                          */

static const uint32_t check = 0xDEADBEEF;
/*pbkdfval is defined to be at least as big as PBKDF_ITERATIONS + uint16_t*/
typedef uint64_t pbkdfval;

#define SALTSIZE 16

#endif

