
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

#include <string.h>

#include <pthread.h>
#include <limits.h>

#include <gmp.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>

#include "rsa.h"
#include "rsa_extrafuncs.h"
#include "rsa_codes.h"

#define SALTSIZE               16

static const uint64_t pbkdfi = PBKDF_ITERATIONS;
static const uint32_t check  = 0xDEADBEEF;

struct ec_info {
    struct RsaPublic pubkey;
    int              bitsize;
    FILE            *fp;
};

struct ec_block_info {
    mpz_t          *num;
    int             blocknum;
    struct ec_info *inf;
};

void *ec_wrapper(void *arg)
{   
    struct ec_block_info blck = *(struct ec_block_info *)arg;

    rsa_encrypt(blck.num, blck.inf->pubkey, blck.inf->bitsize, blck.inf->fp);

    printf("Finished Block %d\n", blck.blocknum);
    return NULL;
}



int filencrypt(const char *pass,
               FILE       *opt,
               FILE       *end,
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
    uint64_t pbkdftot;
    
    pthread_t *threads;

    mpz_t *mpzarr;
    char  *tmpread;
    
    struct RsaPublic  pubkey;
    struct RsaPrivate privkey;
    
    struct ec_info        inf;
    struct ec_block_info *blocks;
    /*Declarations over, lets do some input checks*/



    if (fildes <= (STDERR_FILENO | STDIN_FILENO | STDOUT_FILENO)) {
        return 1;
    }

    if (fstat(fildes, &st)) {
        return 1;
    }

   /*Set some values from entropy*/
    
    fread(salt,      sizeof(char),     SALTSIZE, entropy);
    fread(&pbkdftmp, sizeof(uint16_t), 1,        entropy);
    
    salt[SALTSIZE] = '\0';

    encrypt_buf = calloc(BYTENUM*2 + 1, sizeof(char));
    encrypt_key = fmemopen(encrypt_buf, BYTENUM*2+1, "w+"); //the +1 is needed to store EOF in accordance with the standard

    if (gen_entropy(pass, salt, encrypt_key, BYTENUM*4, pbkdftmp+pbkdfi)) {
        return 1;
    }

    fseek(encrypt_key, 0, SEEK_SET);

    rsa_genkeys(&pubkey, &privkey, bitnum, encrypt_key);
    
    gmp_printf("Pubkey: \n%ZX\n", pubkey.mod);
    
    #define OVERFLOW (st.st_size % BYTENUM != 0)
    #define MAINSIZE (st.st_size - (st.st_size % BYTENUM))
    
    finsize = (SALTSIZE + sizeof(uint64_t) + sizeof(uint32_t) + BYTENUM*2*(OVERFLOW+1) + MAINSIZE);
             /*Obvious    our constant debugs                 we need 2 extra             our main file *
              *           DEADBEEF unencrypted,               blocks, one for                           *
              *                                               DEADBEEF encrypted,                       *
              *           and our PBKDFI val                  and one for overflow                      */
    
    printf("%d\n", finsize);

    fin = calloc(finsize+1, sizeof(char));
    ret = fmemopen(fin, finsize+1, "w+");

    pbkdftot = pbkdftmp+pbkdfi; //Total PBKDF Iterations
    fwrite(&salt,     sizeof(char), SALTSIZE, ret);
    fwrite(&pbkdftot, sizeof(uint64_t), 1, ret);
    fwrite(&check,    sizeof(uint32_t), 1, ret);

    mpz_t chmpz;
    mpz_init(chmpz);
    mpz_set_ui(chmpz, check);

    numops = (OVERFLOW + MAINSIZE/BYTENUM);
              /*only add 1 if we have more*
               *bytes than we can store in*
               *a 2048 block              */
    
    threads = malloc(sizeof(pthread_t)*numops);

    mpzarr = filtompz(opt, numops, BYTENUM);

    if (!mpzarr) {
        return 1;
    }
    
    printf("File size: %d\n", (int)st.st_size);
    printf("mpzbuf filled.\nNumber of Operations needed: %d\n\n", numops);
    
    tmpread = calloc(sizeof(char), BYTENUM*2);
    if (!tmpread) {
        return 1;
    }

    rsa_encrypt(&chmpz, pubkey, bitnum, entropy);
    
    buffrommpz(&chmpz, tmpread, BYTENUM*2);
    fwrite(tmpread, sizeof(char), BYTENUM*2, ret);
    
    
    inf.pubkey  = pubkey;
    inf.bitsize = bitnum;
    inf.fp      = entropy;
    
    blocks      = calloc(numops, sizeof(struct ec_block_info));
    
    for (int i=0; i<numops; i++) {
        blocks[i].inf      = &inf;
        blocks[i].num      = &mpzarr[i];
        blocks[i].blocknum = i;
        
        pthread_create(&threads[i], NULL, ec_wrapper, (void *)&blocks[i]);
    }

    for (int i=0; i<numops; i++) {
        printf("Joining Block %d\n", i);
        pthread_join(threads[i], NULL);
    }

    free(blocks);

    printf("Threads Completed\nWriting data.\n\n");

    /* So now we have a fully encrypted array of mpz integers. *
     * We'll write that to a buffer, and then we'll just write *
     * the buffer to the file.                                 */
    
    memset(tmpread, 0, BYTENUM*2);

    for (int i=0; i<numops; i++) {
        memset(tmpread, 0, BYTENUM*2);
        buffrommpz(&mpzarr[i], tmpread, BYTENUM*2);
        fwrite(tmpread, sizeof(char), BYTENUM*2, ret);
    }
    
    tmpread = realloc(tmpread, finsize);
    if (!tmpread) {
        return 1;
    }
    memset(tmpread, 0, finsize);

    fseek(ret, 0, SEEK_SET);
    
    fread(tmpread,  sizeof(char), finsize, ret);
    fwrite(tmpread, sizeof(char), finsize, end);

    free(mpzarr);
    free(threads);

    free(tmpread);
    
    fclose(encrypt_key);
    free(encrypt_buf);

    fclose(ret);
    free(fin);
    
    return 0;
}

