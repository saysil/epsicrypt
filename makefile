
NAME    = epsicrypt

CC      = gcc

INC     = inc/

OBJ_DIR = obj/

SRC_DIR = src/


INS_DIR = /usr/bin

_D      = 

#Uncomment these lines to make modifications to PBKDF values
#_D     += -DPBKDF_OAEP_CUSTOM=[Your Value]
#_D     += -DPBKDF_OAEP_FAST
_D     += -DPBKDF_CUSTOM=5000

#Uncomment these to make thread modifications, a good value is your CPUs cores - 1
_D     += -DMAXTHREADS=7

#options for GPU computing (not yet implemented)
#_D     += OPENCL
#_D     += CUDA
#_D     += CPU

CFLAGS  = -Wall -std=gnu99 -O2 -I $(INC)


DEPS    = $(wildcard $(INC)*.h)

SRC     = $(wildcard $(SRC_DIR)*.c)

_OBJ    = $(SRC:.c=.o)

OBJ     = $(_OBJ:$(SRC_DIR)%=$(OBJ_DIR)%)

_F      = $(patsubst $(OBJ_DIR)%, $(SRC_DIR)%, $@)


LINK    = -lgmp -lcrypto -lpthread


$NAME: $(DEPS) $(OBJ)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJ) $(LINK)
	
$(OBJ): $(SRC)
	$(CC) -c $(CFLAGS) $(_D) -o $@ $(patsubst %.o, %.c, $(_F))

clean: 
	rm $(OBJ)
	rm $(NAME)

.PHONY: clean;

install: $(NAME)
	install -m=755 $(NAME) $(INS_DIR)

.PHONY: install
