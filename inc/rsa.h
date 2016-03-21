
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

#include "rsa_keys.h"

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

int gen_entropy(const char          *pass,
                const char          *salt,
                FILE                *opt,
                const unsigned int   length,
                const unsigned short pbkdf_extra);

int filencrypt(const char *pass,
               FILE       *opt,
               FILE       *entropy,
               int         bitnum);

#endif

