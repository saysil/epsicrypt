
/*
 * RSA standard functions
 *
 *
 *
 *
 *
 *
 */

#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <gmp.h>
#include "rsa_keys.h"

#include <inttypes.h>

void rsa_freekeypair(struct RsaPublic  *pubkey,
                     struct RsaPrivate *privkey);

int rsa_genkeys(struct RsaPublic    *pubkey,
                struct RsaPrivate   *privkey,
                const unsigned short bitcount,
                FILE                *fp);

int rsa_encrypt(mpz_t                 *num,
                const struct RsaPublic pubkey,
                const int              bitsize,
                FILE                  *fp);

int rsa_decrypt(mpz_t                  *num,
                const struct RsaPrivate privkey,
                const int               bitsize,
                FILE                   *fp); 
//The entropy here does not matter; it does not change the value of the decryption

mpz_t *filtompz(FILE               *opt,
                const unsigned int nummpz,
                const unsigned int bytenum);
              

int gen_entropy(const char          *pass,
                const unsigned char *salt,
                FILE                *opt,
                const size_t         length,
                const unsigned short pbkdf_extra);

int filencrypt(const char *pass,       /* Minimum File perms: */
               FILE       *opt,        /* -r-- --- ---        */
               FILE       *end,        /* --w- -r- -r-        */
               FILE       *entropy,    /* -r-- -r- -r-        */
               uint32_t    bitnum,
               char        debug);

int fildecrypt(const char *pass,
               FILE       *opt,        /* -r-- --- ---        */
               FILE       *end,        /* --w- -r- -r-        */
               FILE       *entropy,    /* -r-- -r- -r-        */
               char        debug);

#endif

