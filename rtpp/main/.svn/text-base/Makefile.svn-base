INCLUDE = -I$(MODULE_DIR)/RTPP
INCLUDE += -I$(MODULE_DIR)/PING 
INCLUDE += -I$(MODULE_DIR)/RouterAgent
INCLUDE += -I$(COMM_DIR)/OSAL

ifdef INCLUDE_MON
INCLUDE += -I$(APP_COMM_DIR)/monitor/
endif

SCRS := $(wildcard *.c)
DEPS := $(patsubst %.c, %.d, $(SCRS))
OBJE := $(patsubst %.c, %.o, $(SCRS))

TARG := main
CC = gcc

FLAGS = -Wall -g -O0 $(INCLUDE) -DHAVE_CONFIG_H -D$(PRODUCT) 

ifdef INCLUDE_MON
FLAGS += -DINCLUDE_MON
endif

all : $(OBJE)
	$(LD) -r -o $(TARG) $(OBJE)

$(OBJE):%.o: %.c
	$(CC) -c $(FLAGS) $< -o $@

%.d: %.c
	@set -e; rm -f $@; \
	    $(CC) $(FLAGS) -MM $< > $@.$$$$; \
	    sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	    rm -f $@.$$$$

-include $(DEPS)

.PHONY:clean
clean:
	-rm -f $(OBJE) $(TARG) $(DEPS) 

