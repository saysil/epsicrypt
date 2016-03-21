
/*
 * Generate Entropy from password
 *
 *
 *
 *
 *
 *
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "rsa_codes.h"

#define PASS_ITERATIONS 10000 //actually a better idea to store the iterations as a psuedo-salt

//Returns 0 on success, 1 on error
int gen_entropy(const char          *pass,
                const char          *salt,
                FILE                *opt,
                const unsigned int   length,
                unsigned short       extra_iterations) //file to be written to
{
    unsigned char *tmp = malloc(length);

    if (!PKCS5_PBKDF2_HMAC(pass, strlen(pass),
          (unsigned char *)salt, strlen(salt),
                           PASS_ITERATIONS + extra_iterations, 
                           EVP_sha512(), 
                           length, tmp)) {
        return 1;
    }

    fwrite(tmp, sizeof(char), length, opt);
    
    free(tmp);

    return 0;
}


