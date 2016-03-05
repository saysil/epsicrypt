
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

//Returns 0 on success, 1 on error
int gen_entropy(const char          *pass,
                const char          *salt,
                FILE                *opt,
                const unsigned int   length) //file to be written to
{
    unsigned char *tmp = malloc(length);

    if (!PKCS5_PBKDF2_HMAC(pass, strlen(pass),
          (unsigned char *)salt, strlen(salt),
                           PBKDF_ITERATIONS + 15750, //because 15750 is a cool number
                           EVP_sha512(), 
                           length, tmp)) {
        return 1;
    }

    fwrite(tmp, sizeof(char), length, opt);

    return 0;
}


