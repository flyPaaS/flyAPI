#ifndef __RTPP_COMMON_H__
#define __RTPP_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <ctype.h>
#include <termios.h>
#include <sys/resource.h>
#include <math.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/time.h>

#include "OSAL.h"

#define RTPP_COMMAND_SOCKET_LEN 32
#define RTPP_MAX_LOCAL_NUM 		4
#define RTPP_MAX_RTPC_NUM 		4
#define RTPP_ALLOC_PORT_NUM  	10000
#define RTPP_MAX_CALLID_LEN 	64
#define RTPP_MAX_RECORD_CALLID 	256
#define RTPP_MAX_RECORD_DIR 	64
#define RTPP_MAX_COOKIE_LEN 	64
#define RTPP_MAX_TAG_LEN 		64
#define RTPP_MAX_ARGC_NUM 		10
#define RTPP_MAX_NOTIFY_LEN 	64
#define RTPP_MAX_IP_LEN 		16
#define RTPP_PTHREAD_NUM 		15
#define RTPP_MSG_MAX_LEN 		(32*1024)
#define RTP_PACKET_MAX_LEN 		(8*1024)
#define	TOS						0xb8


#define RET_ERR 		-1
#define RET_OK 		0


#define PORT_NUM_MAX	4
#define PORT_ALL			-1


enum{
	RTPP_ERR_NO_SS=1,
	RTPP_ERR_RECORD_CALLID,
	RTPP_ERR_LINK_ADDR,
	RTPP_ERR_NO_RESORCE,
	RTPP_ERR_INIT_FEC,
	RTPP_ERR_CREAT_CONFERRENCE,
	RTPP_ERR_DEL_CONFERRENCE,
	RTPP_ERR_ADD_PARTICIPANT,
	RTPP_ERR_DEL_PARTICIPANT,
	RTPP_ERR_CALLEEMEDIA_ERROR,
};

typedef enum
{
	RTPP_BRANCHE_ALL = -1,
	RTPP_BRANCHE_LEFT = 0,
	RTPP_BRANCHE_RIGHT=1,
	RTPP_BRANCHE_MAX
}rtppbranche_t;



OSAL_INT32 rtpp_create_sock(OSAL_CHAR *ip, OSAL_UINT16 port,OSAL_INT32 tos,OSAL_INT32 sock_type,OSAL_INT32 proto);

OSAL_INT32 rtpp_udp_send(OSAL_INT32 sock,OSAL_CHAR *pbuf,OSAL_INT32 len,OSAL_INT32 ipvalue,OSAL_INT32 port);

OSAL_INT32 rtpp_udp_trans(OSAL_INT32 sock,OSAL_CHAR *pbuf,OSAL_INT32 len,OSAL_INT32 ipvalue,OSAL_INT32 port);

OSAL_INT32 get_rand_num();


#endif
