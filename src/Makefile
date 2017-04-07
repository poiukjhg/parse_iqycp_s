PWD = $(shell pwd)
PACKET_PATH = $(PWD)/..
SRC_PATH = $(PWD)
EV_DIR = $(PACKET_PATH)/libev

CC= gcc
OBJS = ipSer

INCFILE = -I$(EV_DIR)
MY_LIBS = -L$(EV_DIR)/.libs
MY_FLAGS = -Wl,-Bstatic -lev -Wl,-Bdynamic -lm -lpthread -lpcap
CFLAGS   += -Wall  -pg -fPIC  $(INCFILE) $(MY_LIBS) $(MY_FLAGS) 

EV_OBJECTS = libev.a
OBJECTS = mylock.o reg_handler.o parse_handler.o server_handler.o main.o 

.PHONY: all clean 
all: $(OBJS) 
$(OBJS):$(OBJECTS) $(EV_OBJECTS)
	$(CC)  -o $@  $(OBJECTS) $(CFLAGS)
$(EV_OBJECTS):
	cd $(EV_DIR) && sh $(EV_DIR)/autogen.sh
	cd $(EV_DIR) && $(EV_DIR)/configure
	cd $(EV_DIR) && make
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@			
clean:
	cd $(EV_DIR) && make clean
	rm -rf $(OBJS)
	rm -rf *.o 
	rm -rf *.out

