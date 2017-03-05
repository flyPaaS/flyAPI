CC = g++

FLAGS = -O0 -Wall
CFLAGS = -O0 -Wall


all :
	$(MAKE) -C RTPP
	$(MAKE) -C PING
	$(MAKE) -C NOTIFY  
	$(MAKE) -C RA

clean:
	$(MAKE) clean -C RTPP
	$(MAKE) clean -C PING
	$(MAKE) clean -C NOTIFY 
	$(MAKE) clean -C RA
