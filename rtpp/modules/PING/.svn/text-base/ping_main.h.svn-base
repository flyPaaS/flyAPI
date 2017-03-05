/*************************************************************************
  *** Auth           :   Wanglei
  *** File             :   ping_main.h
  ***Purpose        :   get other RTPP network-parameter
*************************************************************************/

#ifndef _PING_MAIN__H_
#define _PING_MAIN__H_
#define MAX_RTPP_COUNT 4
#define MAX_RTPC_COUNT 4
#define IP_LEN 16
#define PING_REPEAT 10
#define PACKET_SIZE 2048
#define DATA_LEN 56
#define MAX_IP_NUM 2000
#define MAX_TTL_TIME 26*60*60

typedef enum
{	
	ICMP_ECHOREPLY = 0,
	ICMP_ECHO = 8,
	ICMP_PROBE_T = 20,
	ICMP_REPLY_T,
	ICMP_SHELL_PROBE_T,
	ICMP_SHELL_REPLY_T
}icmpType;

typedef enum
{
	eDISABLE,
	eENABLE
}enable_T;

typedef struct
{
	OSAL_BOOL initialized;
	OSAL_BOOL isEnable;
	OSAL_INT32 ping_rate;
	OSAL_INT32 respond_sdk_port;
	struct sockaddr_in report_addr[MAX_RTPC_COUNT];
	OSAL_INT32 rtpc_num;
	OSAL_CHAR  localip[MAX_RTPP_COUNT][IP_LEN];
	OSAL_INT32 localipnum;
	OSAL_TIMER_ID timerid_ping_rate;
	OSAL_TIMER_ID timerid_report_rate;	
	OSAL_TIMER_ID timerid_check_gw_active;
	OSAL_TIMER_ID timerid_ping_ip;
	OSAL_TIMER_ID timerid_heart_beat;
	OSAL_INT32 ping_times;
	OSAL_INT32 hb_times;
}PingGlobalsT;

typedef enum
{
	RTPP_IP,
	GW_IP
}ip_type;

typedef  struct ipInfo_t
{
         OSAL_CHAR    ip[IP_LEN];
         OSAL_INT32   delay[PING_REPEAT*2];;		 
         OSAL_INT32   sended;		 
         OSAL_INT32   received;			 
		 ip_type	  iptype;
		 time_t 	  ttl;
}ipInfo_t;

typedef struct pingNode
{
	OSAL_CHAR		rtppIp[IP_LEN];
	OSAL_INT32 		pingSock;
	OSAL_INT32 		reportSock;
	OSAL_INT32 		respondSdkSock;
	OSAL_HHASH	  	resultHash;
	
}pingNode;

#define PING_LABEL_HOST_IP 				"RTPP_HOST_IP"
#define PING_LABEL_RTPC_IP 				"RTPP_RTPC_IP"
#define PING_LABEL_PING_RATE			"PING_RATE"
#define PING_LABEL_COLONY 				"PING_COLONY"

OSAL_INT32 ping_init (void);
OSAL_INT32 ping_main(OSAL_msgHdr *pMsg);
void ping_end (void);
void ping_init_shell ();

#endif






