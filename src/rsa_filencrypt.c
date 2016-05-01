
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

static const uint32_t pbkdfi = PBKDF_ITERATIONS;

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
} //Wrapper for multithreading



int filencrypt(const char *pass,
               FILE       *opt,
               FILE       *end,
               FILE       *entropy,
               uint32_t    bitnum)
{  
    #define BYTENUM (bitnum/CHAR_BIT)

    struct stat st;
    int         fildes = fileno(opt);

    unsigned char  salt[SALTSIZE+1];

    int finsize;
    int numops; //number of encryption operations we need to do
    
    char *fin;
    FILE *ret;
    char *encrypt_buf;
    FILE *encrypt_key;
    
    uint32_t overval;

    uint16_t pbkdftmp;
    pbkdfval pbkdftot;
    
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
    /*Variable length pbkdf*/
    


    for (int i=0; i<SALTSIZE; i++) {
        salt[i] = (salt[i] % (UCHAR_MAX - ' ')) + ' ';
    } //transform our salt into an ASCII string
    salt[SALTSIZE] = '\0';



    encrypt_buf = calloc(BYTENUM*2 + 1, sizeof(char));
    encrypt_key = fmemopen(encrypt_buf, BYTENUM*2+1, "w+"); 
    //the +1 is needed to store EOF in accordance with the standard



    if (gen_entropy(pass, salt, encrypt_key, BYTENUM*2, pbkdftmp+pbkdfi+PBKDF_MIN)) {
        return 1;
    }



    fseek(encrypt_key, 0, SEEK_SET);
        
    rsa_genkeys(&pubkey, &privkey, bitnum, encrypt_key);
    
    gmp_printf("Pubkey: \n%ZX\n", pubkey.mod);
    
    overval = (st.st_size % BYTENUM);

    #define OVERFLOW (st.st_size % BYTENUM != 0)
    #define MAINSIZE (st.st_size - overval)
    
    finsize = (SALTSIZE + sizeof(pbkdfval) + sizeof(uint32_t) * 3 + BYTENUM*2*(OVERFLOW+1) + MAINSIZE*2);
             /*Obvious    our constant debugs   size of our byte   we need 2 extra      our main file *
              *           DEADBEEF unencrypted, number and         blocks, one for                    *
              *                                 overflow           DEADBEEF encrypted,                *
              *           and our PBKDFI val                       and one for overflow               */
    
    //printf("%d\n", finsize);

    fin = calloc(finsize+1, sizeof(char));
    ret = fmemopen(fin, finsize+1, "w+");



    pbkdftot = pbkdftmp+pbkdfi+PBKDF_MIN; //Total PBKDF Iterations
    fwrite(salt,      sizeof(char), SALTSIZE, ret);
    fwrite(&bitnum,   sizeof(uint32_t), 1, ret);
    fwrite(&pbkdftot, sizeof(pbkdfval), 1, ret);
    fwrite(&overval,  sizeof(uint32_t), 1, ret);
    fwrite(&check,    sizeof(uint32_t), 1, ret);



    mpz_t chmpz;
    mpz_init(chmpz);
    mpz_set_ui(chmpz, check);

    numops = (OVERFLOW + MAINSIZE/BYTENUM);
              /*only add 1 if we have more*
               *bytes than we can store in*
               *a 2048 block              */
    
    threads = calloc(numops, sizeof(pthread_t));
    
    mpzarr = filtompz(opt, numops, BYTENUM);
    
    if (!mpzarr) {
        return 1;
    }
    
    //printf("File size: %d\n", (int)st.st_size);
    printf("mpzbuf filled.\nNumber of Operations needed: %d\n\n", numops);
    
    tmpread = calloc(sizeof(char), BYTENUM*2);
    if (!tmpread) {
        return 1;
    }

    rsa_encrypt(&chmpz, pubkey, bitnum, entropy);
    
    buffrommpz(&chmpz, tmpread, BYTENUM*2);
    fwrite(tmpread, sizeof(char), BYTENUM*2, ret);
    //write check

    mpz_clear(chmpz);
    
    inf.pubkey  = pubkey;
    inf.bitsize = bitnum;
    inf.fp      = entropy;
    
    blocks      = calloc(numops, sizeof(struct ec_block_info));
    
    for (int i=0; i<numops; i++) {
        blocks[i].inf      = &inf;
        blocks[i].num      = &mpzarr[i];
        blocks[i].blocknum = i;
        
        pthread_create(&threads[i], NULL, ec_wrapper, (void *)&blocks[i]);
    } //create threads for encryption

    for (int i=0; i<numops; i++) {
        //printf("Joining Block %d\n", i);
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

        //printf("%d\n", strlen(tmpread));
        
        fwrite(tmpread, sizeof(char), BYTENUM*2, ret);
    } //write the encrypted file
    //TODO: put this in seperate function. mpztofil?
    
    printf("%d\n", finsize);

    tmpread = realloc(tmpread, finsize);
    if (!tmpread) {
        return 1;
    }
    memset(tmpread, 0, finsize);

    fseek(ret, 0, SEEK_SET);
    
    fread(tmpread,  sizeof(char), finsize, ret);
    fwrite(tmpread, sizeof(char), finsize, end);
    
    for (int i=0; i<numops; i++) {
        mpz_clear(mpzarr[i]);
    } //clear out all the mpzs

    free(mpzarr);
    free(threads);
    
    free(tmpread);
    
    fclose(encrypt_key);
    free(encrypt_buf);

    fclose(ret);
    free(fin);
    
    rsa_freekeypair(&pubkey, &privkey);

    return 0;
}

