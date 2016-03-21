
/*
 * Wrapper around gen_entropy and rsa_encrypt to encrypt files
 *
 *
 *
 *
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pthread.h>
#include <limits.h>

#include <gmp.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>

#include "rsa.h"
#include "rsa_codes.h"

#define SALTSIZE               16

static const uint64_t pbkdfi = PBKDF_ITERATIONS;
static const uint32_t check  = 0xDEADBEEF;

int filencrypt(const char *pass,
               FILE       *opt,
               FILE       *entropy,
               int         bitnum)
{  
    #define BYTENUM (bitnum/CHAR_BIT)

    struct stat st;
    int         fildes = fileno(opt);

    char  salt[SALTSIZE+1];

    int finsize;
    int numops; //number of encryption operations we need to do
    
    char *fin;
    FILE *ret;
    char *encrypt_buf;
    FILE *encrypt_key;

    uint16_t pbkdftmp;
    
    pthread_t *threads;

    if (fildes <= (STDERR_FILENO | STDIN_FILENO | STDOUT_FILENO)) {
        return 1;
    }

    if (fstat(fildes, &st)) {
        return 1;
    } 
    
    fread( salt,     sizeof(char),     SALTSIZE, entropy);
    fread(&pbkdftmp, sizeof(uint16_t), 1,        entropy);
    
    salt[SALTSIZE] = '\0';

    encrypt_buf = malloc(BYTENUM*2);
    encrypt_key = fmemopen(encrypt_buf, BYTENUM*2, "rw");

    if (gen_entropy(pass, salt, encrypt_key, BYTENUM*2, pbkdftmp+pbkdfi)) {
        return 1;
    }
    
    finsize = (SALTSIZE + sizeof(uint64_t) + sizeof(uint32_t)  + BYTENUM*2 + (st.st_size - (st.st_size % BYTENUM)));
             /*Obvious    our constant debugs                    we need 2 extra       our main file *
              *           DEADBEEF unencrypted,                  blocks, one for                     *
              *                                                  DEADBEEF encrypted,                 *
              *           and our PBKDFI val                     and one for overflow                */

    fin = malloc(finsize);
    ret = fmemopen(fin, finsize, "w");

    uint64_t pbkdftot = pbkdftmp+pbkdfi;   
    fwrite(&salt,     sizeof(char), SALTSIZE, ret);
    fwrite(&pbkdftot, sizeof(uint64_t), 1, ret);
    fwrite(&check,    sizeof(uint32_t), 1, ret);

    mpz_t chmpz;
    mpz_init(chmpz);
    mpz_set_ui(chmpz, check);

    numops = (1 + ((st.st_size - (st.st_size % BYTENUM)) / BYTENUM));

    
    
    threads = malloc(sizeof(pthread_t)*numops);
    
    //TODO: set mpz array, and add concurrency
    
    
    fclose(encrypt_key);
    free(encrypt_buf);

    fclose(ret);
    free(fin);
    
    return 0;
}

