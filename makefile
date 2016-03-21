
NAME    = epsicrypt

CC      = gcc

INC     = inc/

OBJ_DIR = obj/

SRC_DIR = src/


INS_DIR = /usr/bin


CFLAGS  = -Wall -std=gnu99 -O2 -I $(INC) 


DEPS    = $(wildcard $(INC)*.h)

SRC     = $(wildcard $(SRC_DIR)*.c)

_OBJ    = $(SRC:.c=.o)

OBJ     = $(_OBJ:$(SRC_DIR)%=$(OBJ_DIR)%)

_F      = $(patsubst $(OBJ_DIR)%, $(SRC_DIR)%, $@)


LINK    = -lgmp -lcrypto -lpthread



$NAME: $(DEPS) $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(CFLAGS) $(LINK)
	
$(OBJ): $(SRC)
	$(CC) -c -o $@ $(patsubst %.o, %.c, $(_F)) $(CFLAGS)

clean: 
	rm $(OBJ)
	rm $(NAME)

.PHONY: clean;

install: $(NAME)
	install -m=755 $(NAME) $(INS_DIR)

.PHONY: install
