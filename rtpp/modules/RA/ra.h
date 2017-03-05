#ifndef _RA_H_
#define _RA_H_

#include <stdio.h>
//#include <errno.h>
//#include <time.h>
#include <getopt.h>
#include <stdlib.h>

//#include <string.h>
//#include <stddef.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in_systm.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <json/json.h>


#include "common.h"

#define TCP_BUFF_LEN 1024

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#define RA_ROUTER_LIST "ROUTER_LIST"
#define RA_AGENT_ADDR  "AGENT_ADDR"
#define RA_AGENT_ADDR_BAK  "AGENT_ADDR_BAK"
#define RA_PING_PKT_INTV "PING_PKT_INTERVAL"
#define RA_PING_CALC_INTV "PING_CALC_INTERVAL"
#define RA_COST_THRESHOLD "NBR_COST_THRESHOLD"

#define BODY_TYPE_JSON  0X00
#define BODY_TYPE_XML   0X01
#define BODY_TYPE_TLV   0X02

enum RA_MSG_TYPE
{
	RA_REG_REQ,
	RA_REG_RSP,
	RA_HB_REQ,
	RA_HB_RSP,
	RA_NB_STAT_REP = 7,
	RA_NB_LIST = 10,
};

enum RA_RECFG_MSG
{
	RECFG_AGENT_ADDR,
	RECFG_PKT_INTV,
	RECFG_CALC_INTV,
};

#ifndef OSAL_UCHAR
typedef unsigned char OSAL_UCHAR;
#endif

typedef enum
{
	TIMER_TX_HB,
	TIMER_CALC_PING,
	TIMER_TX_PING,
	TIMER_TCP_CONNECT,
}RA_TIMER_E;

typedef struct
{
	OSAL_UCHAR msg_type;
	OSAL_UCHAR body_type;
	OSAL_UINT16 sn;
	OSAL_UINT16 body_len;
	OSAL_INT8 body[0];
}__attribute__((packed))ra_msg;

typedef enum 
{
	RA_INVALID,
	RA_SOCK_INITED,
	RA_SOCK_CONNED,
	RA_REGISTED,
}RA_STATUS_E;


typedef struct 
{
	OSAL_INT32	sock;
	RA_STATUS_E status;
	OSAL_TIMER_ID tcp_timer;
	OSAL_UINT16	router_port;
	OSAL_CHAR	router_ip_str[32];
	OSAL_CHAR	self_ip_str[32];
	OSAL_CHAR	bak_ip_str[32];
	OSAL_CHAR 	bakFlag;//0:Œ¥≈‰÷√bakµÿ÷∑£¨1:≈‰÷√¡Àbakµÿ÷∑
	OSAL_CHAR	bakStatus;//0:Œ¥◊¢≤·£¨1:“—◊¢≤·
	OSAL_INT32  hb_loss_cnt;
	OSAL_INT8	rcv_buf[1024*2];
	OSAL_INT32 	rcv_len;
	OSAL_INT32  conn_times;
}tcp_conn_t;

typedef struct _stat_
{
	OSAL_UINT64 rxCounts;
	OSAL_UINT64 rxBytes;
	OSAL_UINT64 txCounts;
	OSAL_UINT64 txBytes;
	OSAL_INT32  concurrency;
	OSAL_INT32  ipConcurrency;
}flowStat;


OSAL_INT32 tx_tcp_msg_json(OSAL_UCHAR type,Json::Value &value);
void ra_show_conf();
void ra_set_conn_addr(const OSAL_CHAR *ipaddr,OSAL_INT32 port);


extern OSAL_INT32 test_mode;
extern OSAL_INT8 disc_rtpp[];

//OSAL_INT32 ra_init (void);
//OSAL_INT32 ra_main(OSAL_msgHdr *pMsg);
//void ra_end(void);

#endif
