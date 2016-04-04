
#include <stdio.h>
#include <gmp.h>

#include <pthread.h>

#include "rsa.h"

int main(int argc, char *argv[])
{
    /*struct RsaPublic  pubkey;
    struct RsaPrivate privkey;
    
    mpz_t a;
    
    mpz_init(a);

    mpz_set_str(a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
    
    printf("Size: %d\n", mpz_sizeinbase(a, 2));

    //gmp_printf("%ZX\n", a);

    FILE *fp = fopen("/dev/urandom", "r");
    
    rsa_genkeys(&pubkey, &privkey, 2048, fp);

    printf("Mod size: %d\n", mpz_sizeinbase(privkey.mod, 2));

    printf("Encrypt: %d\n\n", rsa_encrypt(&a, pubkey, 2048, fp));
    
    gmp_printf("Encrypted: %ZX\n", a);

    printf("\nDecrypt: %d\n\n", rsa_decrypt(&a, privkey, 2048, fp));

    gmp_printf("%ZX\n", a);*/

    FILE *entropy = fopen("/dev/urandom", "r");
    FILE *opt     = fopen("./test",       "r");
    FILE *fin     = fopen("./test.eps",   "w");
    
    filencrypt("Ayyyy Lammow", opt, fin, entropy, 2048);
 
    return 0;
}

