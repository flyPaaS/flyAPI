
CC = g++
TARGET = rtpp 

FLAGS =  -O0 -Wall
CFLAGS =  -O0 -Wall

RTPP_DIR  = $(MODULE_DIR)/RTPP/
PING_DIR  = $(MODULE_DIR)/PING/
NOTIFY_DIR = $(MODULE_DIR)/NOTIFY/
RA_DIR = $(MODULE_DIR)/RA/
OSAL_DIR = $(COMM_DIR)/OSAL
MAIN_DIR = $(RTPP_APP_DIR)/main

PRJ_OBJS   = $(MAIN_DIR)/main  $(RTPP_DIR)/RTPP  $(PING_DIR)/PING $(OSAL_DIR)/OSAL $(NOTIFY_DIR)/NOTIFY  $(RA_DIR)/RA
#PRJ_OBJS   = $(MAIN_DIR)/main  $(RTPP_DIR)/RTPP  $(PING_DIR)/PING $(OSAL_DIR)/OSAL $(NOTIFY_DIR)/NOTIFY
#LD_OPTIONS =  -lpthread  -lm -lreadline -lncurses  -lFecProcess -ljsoncpp.so
LD_OPTIONS =  -lpthread  -lm -lreadline -lncurses  -lFecProcess $(RTPP_APP_DIR)/lib/libjsoncpp.a

ifdef INCLUDE_MON
PRJ_OBJS += $(APP_COMM_DIR)/monitor/mon
LD_OPTIONS += /usr/local/lib/libnet.a
endif

LD_OPTIONS += -lrt -ldl -lmixer_all

all :
	$(MAKE) -C $(COMM_DIR) PRODUCT=RTPP
	$(MAKE) -C $(MODULE_DIR) PRODUCT=RTPP
	$(MAKE) -C $(MAIN_DIR) PRODUCT=RTPP
	$(MAKE) -C $(APP_COMM_DIR) PRODUCT=RTPP
	cp -rf ./install/libmixer_all.so /lib64/
	$(CC) -o  $(TARGET) $(PRJ_OBJS) $(LD_OPTIONS)


clean:
	-rm -f $(TARGET)
	-rm -f *.o
	$(MAKE) clean -C $(COMM_DIR)
	$(MAKE) clean -C $(MODULE_DIR)
	$(MAKE) clean -C $(MAIN_DIR)
	$(MAKE) clean -C $(APP_COMM_DIR)
	
install: all
	@echo
	@echo "installing, please wait for. . ."
	@mkdir -p /var/log/rtpp #&> /dev/null
	@mkdir -p /root/.rtpp
#ulimit -n 5120
	@echo

	echo "copying file. . ."
	cp -rf rtpp    /usr/local/sbin/
	chmod +x /usr/local/sbin/rtpp
	cp -rf ./install/rtppmon /etc/rc.d/init.d/
	chmod +x /etc/rc.d/init.d/rtppmon
	cp -rf ./install/rtpp_monitor.sh /usr/local/sbin/
	chmod +x /usr/local/sbin/rtpp_monitor.sh
	-mkdir -p /root/.rtpp/profile
	-mkdir -p /root/.rtpp/voice
#cp -rf ./install/profile/rtpp.conf   /root/.rtpp/profile
#	cp -rf ./install/profile/ping.conf   /root/.rtpp/profile
	cp -fr ./install/voice/* /root/.rtpp/voice
	@echo
	@echo "install end"


uninstall:
	@echo
	@echo "uninstalling, please wait for. . ."
	@echo

	@echo "removing file. . ."
	-@rm -rf /var/log/rtpp
	-@rm -rf /root/.rtpp/voice
	@echo

	-@rm -rf /usr/local/sbin/rtpp
	-@rm -rf /etc/rc.d/init.d/rtppmon

	@echo "uninstall end"

rpm: install
	rpmbuild -bb ./rpm.spec
	@echo "rpm end"

