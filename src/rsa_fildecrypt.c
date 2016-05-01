
/*
 * Decrypt whole file at once
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

#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>

#include <gmp.h>

#include "rsa.h"
#include "rsa_extrafuncs.h"
#include "rsa_codes.h"

struct dc_info {
    struct RsaPrivate privkey;
    uint32_t          bitsize;
    FILE             *fp;
};

struct dc_block_info {
    mpz_t          *num;
    int             blocknum;
    struct dc_info *inf;
};

void *dc_wrapper(void *arg)
{
    struct dc_block_info blck = *(struct dc_block_info *)arg;

    rsa_decrypt(blck.num, blck.inf->privkey, blck.inf->bitsize, blck.inf->fp);

    printf("Finished Block %d\n", blck.blocknum);
    return NULL;

}

int fildecrypt(const char *pass,
               FILE       *opt,
               FILE       *end,
               FILE       *entropy)
{
    unsigned char salt[SALTSIZE + 1];
    uint32_t      bitnum;
    pbkdfval      pbkdftot;
    uint32_t      tmpcheck;
    uint32_t      overval;

    struct stat st;
    int         filedes = fileno(opt);
    
    int finsize;
    int numops; //number of operations, as in filencrypt
    
    char *tmpread;

    mpz_t  chmpz;
    mpz_t *mpzarr;

    struct RsaPublic  pubkey;
    struct RsaPrivate privkey;

    struct dc_info        inf;
    struct dc_block_info *blocks;

    pthread_t *threads;

    #define BYTENUM (bitnum/CHAR_BIT)

    if (filedes <= (STDERR_FILENO | STDIN_FILENO | STDOUT_FILENO)) {
        return 1;  
    }

    if (fstat(filedes, &st)) {
        return 1;
    }

    fread(salt, sizeof(char), SALTSIZE, opt);
    salt[SALTSIZE] = '\0';
    
    //printf("%d\n%s\n", strlen(salt), salt);


    fread(&bitnum,   sizeof(uint32_t), 1, opt);
    //printf("%d\n", bitnum);
    fread(&pbkdftot, sizeof(pbkdfval), 1, opt);
    //printf("%d\n", pbkdftot);
    fread(&overval,  sizeof(uint32_t), 1, opt);
    printf("Overflow: %d\n", overval);
    fread(&tmpcheck, sizeof(uint32_t), 1, opt);
    
    if (tmpcheck != check) {
        return 1;
    }

    char *encrypt_buf = calloc(BYTENUM*2+1, sizeof(char));
    FILE *encrypt_key = fmemopen(encrypt_buf, BYTENUM*2+1, "w+");


    if (gen_entropy(pass, salt, encrypt_key, BYTENUM*2, pbkdftot)) {
        return 1;
    }
    
    fseek(encrypt_key, 0, SEEK_SET);

    rsa_genkeys(&pubkey, &privkey, bitnum, encrypt_key);

    gmp_printf("Pubkey: \n%ZX\n", pubkey.mod);
    
    #define METADAT (sizeof(char) * SALTSIZE + sizeof(uint32_t) * 3 + sizeof(pbkdfval) + BYTENUM*2)
    /*                salt, obviously,   DEADBEEF unencrypted + bitnum,  pbkdf value,    DEADBEEF encrypted */
    finsize = st.st_size - METADAT;
    
    if (finsize % BYTENUM != 0) {
        return 1;
    }

    printf("%d\n", finsize);
    
    
    numops = finsize / (BYTENUM*2);
    printf("Number of Operations: %d\n", numops);
    


    tmpread = calloc(BYTENUM*2, sizeof(char));
    fread(tmpread, sizeof(char), BYTENUM*2, opt);
    
    

    mpz_init(chmpz);
    mpzfrombuf(&chmpz, tmpread, BYTENUM*2);
    
    rsa_decrypt(&chmpz, privkey, bitnum, entropy);

    gmp_printf("Decrypted: \n%ZX\n", chmpz);
    if (mpz_cmp_ui(chmpz, check)) {
        return 1;
    }

    mpz_clear(chmpz);
    
    mpzarr = calloc(numops, sizeof(mpz_t));

    for (int i=0; i<numops; i++) {
        memset(tmpread, 0, BYTENUM*2);
        fread(tmpread, sizeof(char), BYTENUM*2, opt);
        mpzfrombuf(&mpzarr[i], tmpread, BYTENUM*2);
    }
    
    inf.privkey = privkey;
    inf.bitsize = bitnum;
    inf.fp      = entropy;
    
    blocks      = calloc(numops, sizeof(struct dc_block_info));

    threads = calloc(numops, sizeof(pthread_t));

    for (int i=0; i<numops; i++) {
        blocks[i].inf      = &inf;
        blocks[i].num      = &mpzarr[i];
        blocks[i].blocknum = i;

        pthread_create(&threads[i], NULL, dc_wrapper, (void *)&blocks[i]);
    }

    for (int i=0; i<numops; i++) {
        pthread_join(threads[i], NULL);
    }

    free(blocks);

    printf("Threads Completed\nWriting Data.\n\n");

    tmpread = realloc(tmpread, BYTENUM);
    
    for (int i=0; i<numops-1; i++) {
        memset(tmpread, 0, BYTENUM);
        buffrommpz(&mpzarr[i], tmpread, BYTENUM);
        
        fwrite(tmpread, sizeof(char), BYTENUM, end);
        mpz_clear(mpzarr[i]);
    }

    memset(tmpread, 0, BYTENUM);
    buffrommpz(&mpzarr[numops-1], tmpread, BYTENUM);

    fwrite(tmpread, sizeof(char), overval, end);
    //The last block may have less bytes than the other blocks
    //and should be handled specially


    free(mpzarr);
    free(threads);

    free(tmpread);

    fclose(encrypt_key);
    free(encrypt_buf);
    
    rsa_freekeypair(&pubkey, &privkey);

    return 0;
}

