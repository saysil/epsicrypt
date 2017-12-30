
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <gmp.h>

#include <pthread.h>

#include <getopt.h>

#include "rsa.h"

int main(int argc, char *argv[])
{
    /*struct RsaPublic  pubkey;
    struct RsaPrivate privkey;
    
    mpz_t a;
    
    mpz_init(a);

    mpz_set_str(a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
    
    printf("Size: %d\n", mpz_sizeinbase(a, 2));

    gmp_printf("%ZX\n", a);

    FILE *fp = fopen("/dev/urandom", "r");
    
    rsa_genkeys(&pubkey, &privkey, 2048, fp);

    printf("Mod size: %d\n", mpz_sizeinbase(privkey.mod, 2));

    printf("Encrypt: %d\n\n", rsa_encrypt(&a, pubkey, 2048, fp));
    
    gmp_printf("Encrypted: %ZX\n", a);

    printf("\nDecrypt: %d\n\n", rsa_decrypt(&a, privkey, 2048, fp));

    gmp_printf("%ZX\n", a);

    mpz_clear(a);
    rsa_freekeypair(&pubkey, &privkey);
    fclose(fp);*/
    
    #define ERROR   1
    #define INFO    2
    #define WARNING 4
    #define HELP    8
    #define ENCRYPT 16
    #define DECRYPT 32
    
    static const char *hlp = \
    "Usage: epsicrypt -[hepbd] --verbose --quiet\n\n\
    -p: Specify Password used for key generation\n\
    -e file: encrypt a given file using a password\n\
    -d file: decrypt a given file using a password\n\
    -b bitsize: Choose bitsize for rsa\n";
 
    static int vflag  = 0;
    int bitnum = 2048;

    int flags  = 0;

    FILE *tmp  = NULL;
    FILE *end  = NULL;
    char *tmpc = NULL;
    FILE *ent = fopen("/dev/urandom", "r");

    static struct option long_options[] =
    {
        {"verbose",  no_argument,       &vflag, 1},
        {"quiet",    no_argument,       &vflag, 0},
        {"help",     no_argument,       0, 'h'},

        {"encrypt",      required_argument, 0, 'e'},
        {"password",     required_argument, 0, 'p'},
        {"decrypt",      required_argument, 0, 'd'},
        {"rsa_bitsize",  required_argument, 0, 'b'},
        { NULL, 0, NULL, 0 }
    };
    
    char c = 0;
    int option_index = 0;

    char *password = NULL;

    while (1) {
        c = 0;
        option_index = 0;

        c = getopt_long(argc, argv, "vqhe:d:b:p:", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 0:
            break;
        case 'v':
            vflag = 1;
            break;
        case 'q':
            vflag = 0;
            break;
        case 'e':
            tmpc     = optarg;
            flags   |= ENCRYPT;
            break;
        case 'b':
            bitnum   = atoi(optarg);
            break;
        case 'd':
            tmpc     = optarg;
            flags   |= DECRYPT;
            break;
        case 'p':
            password = optarg;
            break;
        default:
            printf("%s\n", hlp);
            exit(1);
            break;
        }

    }
    
    if (tmpc == NULL) {
        return 1;
    }
    if (password == NULL) {
        return 1;
    }

    while (optind < argc && argv[optind][0] != '-') {
        tmp = fopen(tmpc, "rb");
        if (tmp == NULL) {
            return 1;
        }
        
        printf("File: %s\n", tmpc);
        end = fopen(argv[optind], "wb");
        if (end == NULL) {
            return 1;
        }

        if (flags & ENCRYPT) {
            filencrypt(password, tmp, end, ent, bitnum, vflag);
        } else if (flags & DECRYPT) {
            fildecrypt(password, tmp, end, ent, vflag);
        }

        optind++;
    }

    return 0;


    /*int bitnum = 0;
    int flags  = 0;

    int i     = 1;
    FILE *tmp = NULL;
    FILE *end = NULL;

    char *password = NULL;

    FILE *ent = fopen("/dev/urandom", "r");
    
    while (i < argc) { //parse for options
        
        i++;       

    }
    
    if ((flags & DECRYPT) && (flags & ENCRYPT)) {
        flags |= ERROR;
        printf("Encrypt and Decrypt selected. Exiting...\n");
        exit(1);
    }
    
    if (flags < ENCRYPT && ((flags & ERROR) == 0)) { //no option selected, set ENCRYPT by default
        flags |= ENCRYPT;
        printf("Setting encrypt as default.\n");
    }
    //printf ("%d\n", (flags & ERROR) == 0 );
    

    i = 1;
    while (i < argc) { //now parse for files
        
        if (i+1 >= argc || argv[i+1][0] == '-') {
            printf("Destination needed/\n");
        }

        if (argv[i][0] != '-') {
            if (flags & DECRYPT) {
                
                if (!(tmp = fopen(argv[i]), "r")) {
                    flags |= ERROR;
                    printf("Unable to open \'%s\'\n");
                }
                
            } else if (flags & ENCRYPT) {
                
                
                if (!(tmp = fopen(argv[i]), "r")) {
                    flags |= ERROR;
                    printf("Unable to open \'%s\'\n");
                }
                
                

            }
        }

        i+=2;

    }
    //revise this to use getopt
    //
    */
    return 0;
}

