INCLUDE = -I$(COMM_DIR)/OSAL -I$(COMM_DIR)/INCLUDE -I$(APP_COMM_DIR)/libFec

ifdef INCLUDE_MON
INCLUDE += -I$(APP_COMM_DIR)/monitor/
endif

SRC := $(filter-out makeann.c rtpp_log.c rtpp_syslog_async.c, $(wildcard *.c)) 

OBJS := $(patsubst %.c, %.o, $(SRC)) 
DEPS := $(patsubst %.c, %.d, $(SRC))

CFLAGS	= -Wall -g -O0 -D_BSD_SOURCE -DHAVE_CONFIG_H -D_SVID_SOURCE  -D$(PRODUCT) -DSYSTEM_HAS_VM $(INCLUDE) 
#CFLAGS	= -Wall -O2 -D_BSD_SOURCE -DHAVE_CONFIG_H  -D$(PRODUCT) $(INCLUDE) 

ifdef INCLUDE_MON
CFLAGS += -DINCLUDE_MON
endif

ifeq (x86_64, $(findstring x86_64, $(KERNEL_VER)))
    CFLAGS +=-DX86_64
endif

CC = gcc
LD = ld

TARGET  = RTPP 


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
