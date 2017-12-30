
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
                const unsigned char *salt,
                FILE                *opt, //File to be written to
                const size_t         length,
                const unsigned short pbkdf_extra) 
{
    unsigned char *tmp = malloc(length);

    if (!PKCS5_PBKDF2_HMAC(pass, strlen(pass),
                           salt, strlen((char *)salt),
                           pbkdf_extra, 
                           EVP_sha512(), 
                           length, tmp)) {
        return 1;
    }

    fwrite(tmp, sizeof(char), length, opt);

    free(tmp);

    return 0;
}


