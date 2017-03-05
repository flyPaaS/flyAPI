INCLUDE = -I$(COMM_DIR)/OSAL -I$(COMM_DIR)/INCLUDE
INCLUDE += -I./../main -I../

ifdef INCLUDE_MON
INCLUDE += -I$(APP_COMM_DIR)/monitor/
endif


SRC  := $(wildcard *.c) 
OBJS := $(patsubst %.c, %.o, $(SRC))
EXT := $(OBJS)  
DEPS := $(patsubst %.c, %.d, $(SRC))
CFLAGS	= -Wall -g -std=gnu++0x -O0  -D$(PRODUCT)

ifdef INCLUDE_MON
CFLAGS += -DINCLUDE_MON
endif

CFLAGS += $(INCLUDE)

CC = g++ -ldl -pthread
LD = ld

TARGET  = RA


all: $(OBJS)
	$(LD) -r -o $(TARGET) $(EXT)

$(OBJS):%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

%.d: %.c
	@set -e; rm -f $@; \
	    $(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	    sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	    rm -f $@.$$$$

-include $(DEPS) 

clean:
	-rm -f $(TARGET) $(OBJS) $(DEPS) 
	rm -f *.d.*
