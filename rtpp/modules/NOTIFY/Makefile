INCLUDE = -I$(COMM_DIR)/OSAL
INCLUDE += -I./../main

SRC  := $(wildcard *.c) 
OBJS := $(patsubst %.c, %.o, $(SRC)) 
DEPS := $(patsubst %.c, %.d, $(SRC))
CFLAGS	= -Wall -g -O2  -D$(PRODUCT) $(INCLUDE) 

CC = g++
LD = ld

TARGET  = NOTIFY 


all: $(OBJS)
	$(LD) -r -o $(TARGET) $(OBJS)

$(OBJS):%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

%.d: %.c
	@set -e; rm -f $@; \
	    $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	    sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	    rm -f $@.$$$$

-include $(DEPS) 

clean:
	-rm -f $(TARGET) $(OBJS) $(DEPS) *.d.*
