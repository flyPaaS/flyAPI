/*************************************************************************
  *** Auth           :   Wanglei
  *** File             :   ping_main.c
  ***Purpose        :   get other RTPP network-parameter and report to rtpc
*************************************************************************/
#include "common.h"
#include "ping_main.h"
#include "../RTPP/rtpp_session.h"
#include "../RTPP/rtpp_util.h"
#include <netinet/ip_icmp.h>


#define CFG_VALUE_ERROR_HANDLE 		if(!*equ) {\
	OSAL_trace(ePING, eError, "cfg file line %d error in %s.", lines, PING_CFG_FILE);\
	return OSAL_ERROR;\
	}

/*¶¨Ê±Æ÷ID*/
typedef enum
{
	PING_TMR_PINGRATE = 0,
	PING_TMR_REPORTRATE,
	PING_TMR_CHECKACTIVE,
	PING_TMR_PINGIP,
	PING_TMR_HEARTBEAT
}Ping_timer_E;

static pid_t rtpp_pid;
PingGlobalsT PingGlobalData;
//ping_probe_result_T *pProbe_results;
OSAL_HHASH    ipHashTable;
OSAL_HLIST pingResults;


static OSAL_INT32 init_ping_cfg(OSAL_CHAR *buff, OSAL_INT32 lines);
static void ping_out_imcp();   //send imcp to all rtpp
static void ping_process_in_imcp(int fd);
static void respond_sdk_ping(int fd);
//static void control_rtpp_ips(OSAL_msgHdr *pMsg);
static void control_ips(OSAL_msgHdr *pMsg, ip_type type);

static void control_ping_able(OSAL_msgHdr *pMsg);
static void ping_handle_timer (OSAL_timerMsgHdrT *pTimerMsg);
static void commit_results();  // report result to rtpc
static void update_gw_list(); 
static void ping_lauch_action();
static void reset_result_hash(OSAL_HHASH hash);

static OSAL_INT32 unpack_process(OSAL_CHAR *buff, int n, struct sockaddr_in* from, pingNode *pingElem); 
static void complete_result(OSAL_CHAR* ip, OSAL_UINT32 timestamp, pingNode *pingElem);
static void start_timer_ciResults();
static void start_timer_outICMP();
static void start_timer_checkGwActive();
static void start_timer_pingIp();
static void start_timer_send_heartbeat();
static void send_heartbeat_to_rtpc();


/*
static OSAL_INT32 get_rtpc_num(OSAL_CHAR *buff)
{
	OSAL_INT32 flag;
	unsigned long inaddr;
	OSAL_CHAR *rtpc_ip = strchr(buff, '|');
	if(rtpc_ip == OSAL_NULL) {
		OSAL_trace(ePING, eWarn, "update rtpps but rtpc_ip NULL, logic err.");
		return -1;
	}
	*rtpc_ip++= '\0';
	inaddr = inet_addr(rtpc_ip);
	for(flag=0; flag<PingGlobalData.rtpc_num; flag++) {
		if(memcmp((char*)&PingGlobalData.report_addr[flag].sin_addr, (char*)&inaddr, sizeof(inaddr)) ==0)
			break;
	}
	if(flag == PingGlobalData.rtpc_num) {
		OSAL_trace(ePING, eWarn, "not found RTPC, logic err.");
		return -1;
	}
	return flag;
}
*/

OSAL_INT32 create_ping_sock (OSAL_HLIST list )
{
	//init pingSock/reportSock/hashTable
	OSAL_INT32 loc;
	int	optval = -1;
	pingNode *pingElem = OSAL_NULL;
    struct sockaddr_in ping_addr;
    struct sockaddr_in report_addr;
    struct sockaddr_in respond_sdk_addr;
	struct protoent *protocol;
	if( (protocol=getprotobyname("icmp") )==NULL) { 
		OSAL_trace(ePING, eError, "create_ping_sock: getprotobyname err.");
		return OSAL_ERROR;
	}
	if ((loc=OSAL_listGetHeadPos(list))>=0)
	{	
		pingElem = (pingNode *)OSAL_listGetNodeByPos(list, loc);
		
		if(!pingElem)
		{
			OSAL_trace(ePING, eError, "create_ping_sock: get ping results list error.");
			return OSAL_ERROR;
		}
	
		for (; loc>=0 && loc < MAX_RTPP_COUNT; loc=OSAL_listGetNextPos(list, loc))
		{
		
			OSAL_trace(ePING, eDebug, "create_ping_sock: loc is %d", loc);
			pingElem = (pingNode *)OSAL_listGetNodeByPos(list, loc);
		  	if(!pingElem)
		  	{
				continue;
		  	}
			// ping rtpp or gw
			memset(&ping_addr, 0, sizeof(struct sockaddr_in));
			ping_addr.sin_family = AF_INET;
			ping_addr.sin_addr.s_addr = inet_addr(pingElem->rtppIp);
			if((pingElem->pingSock = socket(AF_INET,SOCK_RAW,protocol->p_proto))<0){ 
				OSAL_trace(ePING, eError, "create_ping_sock: socket SOCK_RAW err");
				return OSAL_ERROR;
			}
			optval=1;
			if(setsockopt(pingElem->pingSock, SOL_SOCKET, SO_REUSEADDR ,(void*)&optval, sizeof(optval)) == -1)
			{
				OSAL_trace(ePING, eError,"rtpc_create_sock:setsockopt SO_REUSEADDR err: %s.", strerror(errno));
		        return OSAL_ERROR;
			}
			if(bind(pingElem->pingSock, (struct sockaddr*)&ping_addr, sizeof(ping_addr)) < 0) {
				OSAL_trace(ePING, eError, "create_ping_sock: bind ping addr to rtpp err.");
				return OSAL_ERROR;
			}
			OSAL_trace(ePING, eDebug, "create_ping_sock: create ping socket: %d\n", pingElem->pingSock);
			
			if (OSAL_OK != OSAL_async_select (ePING, pingElem->pingSock, PING_ICMP_IN_MSG, OSAL_NULL, OSAL_NULL))
	  		{
				OSAL_trace (ePING, eError, "create_ping_sock: select raw msgSocket failed.");
				close (pingElem->pingSock);
				return OSAL_ERROR;
		  	}

			//report result to rtpc
			memset(&report_addr, 0, sizeof(struct sockaddr_in));
			report_addr.sin_family = AF_INET;
			report_addr.sin_addr.s_addr = inet_addr(pingElem->rtppIp);
			report_addr.sin_port = htons(7800);		
			if((pingElem->reportSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
				OSAL_trace(ePING, eError, "create_ping_sock: socket UDP sock err.");
				return OSAL_ERROR;
			}
			if(setsockopt(pingElem->reportSock, SOL_SOCKET, SO_REUSEADDR ,(void*)&optval, sizeof(optval)) == -1)
			{
				OSAL_trace(ePING, eError,"rtpc_create_sock:setsockopt SO_REUSEADDR err: %s.", strerror(errno));
				return OSAL_ERROR;
			}

			if(bind(pingElem->reportSock, (struct sockaddr*)&report_addr, sizeof(report_addr)) < 0) {
				OSAL_trace(ePING, eError, "create_ping_sock: bind report addr to rtpc err.");
				return OSAL_ERROR;
			}

			//respond sdk ping
			memset(&respond_sdk_addr, 0, sizeof(struct sockaddr_in));
			respond_sdk_addr.sin_family = AF_INET;
			respond_sdk_addr.sin_addr.s_addr = inet_addr(pingElem->rtppIp);
			respond_sdk_addr.sin_port = htons(PingGlobalData.respond_sdk_port);		
			if((pingElem->respondSdkSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
				OSAL_trace(ePING, eError, "create_ping_sock: socket UDP sock err.");
				return OSAL_ERROR;
			}
			if(setsockopt(pingElem->respondSdkSock, SOL_SOCKET, SO_REUSEADDR ,(void*)&optval, sizeof(optval)) == -1)
			{
				OSAL_trace(ePING, eError,"rtpc_create_sock:setsockopt SO_REUSEADDR err: %s.", strerror(errno));
				return OSAL_ERROR;
			}

			if(bind(pingElem->respondSdkSock, (struct sockaddr*)&respond_sdk_addr, sizeof(respond_sdk_addr)) < 0) {
				OSAL_trace(ePING, eError, "create_ping_sock: bind respond addr to rtpc err.");
				return OSAL_ERROR;
			}
			OSAL_trace(ePING, eDebug, "create respond sdk socket: %d\n", pingElem->respondSdkSock);
			
			if (OSAL_OK != OSAL_async_select (ePING, pingElem->respondSdkSock, PING_SDK_UDP_IN_MSG, OSAL_NULL, OSAL_NULL))
	  		{
				OSAL_trace (ePING, eError, "select respondSdkSock failed.");
				close (pingElem->respondSdkSock);
				return OSAL_ERROR;
		  	}

			
			pingElem->resultHash= OSAL_hashConstruct(MAX_IP_NUM, MAX_IP_NUM, IP_LEN, sizeof(ipInfo_t), "resultHashTable");
			if ( OSAL_NULL == pingElem->resultHash )
			{
				OSAL_trace( ePING, eError, "create_ping_sock: create result hash tbl failed.");
				return OSAL_ERROR;
			}
			
		}
	}
	else
	{		
		OSAL_trace(ePING, eError, "create_ping_sock: ping results list is emply.");	
		return OSAL_ERROR;
	}

	return OSAL_OK;
}


OSAL_INT32 ping_init (void)
{
	pingNode pingnode;
	OSAL_INT32 i;
	
	if(PingGlobalData.initialized) {
		OSAL_trace(ePING, eError, "PING aready initialized yet.");
		return OSAL_ERROR;
	}
	
	memset(&PingGlobalData, 0, sizeof(PingGlobalData));
	PingGlobalData.respond_sdk_port = 7801;
		
	if(init_cfg(CONFIG_FILE, init_ping_cfg) != OSAL_OK) {
		OSAL_trace (ePING, eError, "init cfg file failed.");
		return OSAL_ERROR;
	}
	pingResults = OSAL_listConstruct(sizeof(pingNode), MAX_RTPP_COUNT, "rtpp ping results list");
	if (NULL == pingResults) {
		OSAL_trace (ePING, eError, "Can't construct rtpp ping results list!\n");
		return OSAL_ERROR;
	}

	for(i = 0; i < PingGlobalData.localipnum; i++){
		strncpy(pingnode.rtppIp, PingGlobalData.localip[i], sizeof(pingnode.rtppIp) - 1);
		if(!i)
			OSAL_listAddHeadNode(pingResults, &pingnode);
		else
			OSAL_listInsertNodeByPos(pingResults, OSAL_listGetTailPos(pingResults), &pingnode);
	}
	//create sock
	if(OSAL_OK != create_ping_sock(pingResults)){
		OSAL_trace (ePING, eError, "create ping sock error.");
		return OSAL_ERROR;
	}

	/* create ip hash table*/
	ipHashTable = OSAL_hashConstruct(MAX_IP_NUM, MAX_IP_NUM, IP_LEN, sizeof(ipInfo_t), "ipHashTable");
	if ( OSAL_NULL == ipHashTable )
	{
		OSAL_trace( ePING, eError, "create ip hash tbl failed.");
		return OSAL_ERROR;
	}

	/* send heartbeat */
	start_timer_send_heartbeat();

	/* check the gw ttl */
	start_timer_checkGwActive();
	
	rtpp_pid = getpid();
	
	ping_init_shell ();
	
	PingGlobalData.ping_times = 0;
	PingGlobalData.hb_times = 0;
	PingGlobalData.initialized = OSAL_TRUE;	

	if(PingGlobalData.isEnable) 
		ping_out_imcp();		
	return OSAL_OK;
}

static OSAL_INT32 ping_conf_reload()
{
	OSAL_trace (ePING, eWarn, "ping reload config");
	if(init_cfg(CONFIG_FILE, init_ping_cfg) != OSAL_OK) {
		OSAL_trace (ePING, eError, "init cfg file failed.");
		return OSAL_ERROR;
	}
}

OSAL_INT32 ping_main(OSAL_msgHdr *pMsg)
{	
	switch (pMsg->msgId)
	{
		case PING_ICMP_IN_MSG: 
			ping_process_in_imcp(pMsg->msgSubId);
			break;	  

		case PING_SDK_UDP_IN_MSG:
			respond_sdk_ping(pMsg->msgSubId);
			break;
		
		case eOsalSysMsgIdTimer:	  //timer
		{
			OSAL_timerMsgHdrT *pTimerMsg;
			pTimerMsg = (OSAL_timerMsgHdrT *) pMsg->pContent;
			OSAL_ASSERT_RETURN_VAL (sizeof (OSAL_timerMsgHdrT) == pMsg->contentLen);
			ping_handle_timer (pTimerMsg);
		}
	  	break;
	  
		case PING_CONTROL_RTPP_IPS:
			if(PingGlobalData.isEnable)
				control_ips(pMsg, RTPP_IP);
			break;

		case PING_CONTROL_GW_IPS:
		   	//if(PingGlobalData.isEnable)
		   	control_ips(pMsg, GW_IP);
			break;		

		case PING_CONTROL_ABLE:
			control_ping_able(pMsg);
			break;

		case PING_RELOAD_MSG:
			ping_conf_reload();
			break;
			
		default:
			OSAL_trace(eRTPP, eWarn, "Invalid msg type.%x",pMsg->msgId);
			break;
	}

	return OSAL_OK;	
}

void ping_end (void)
{
	if(!PingGlobalData.initialized)  {
		OSAL_trace(ePING, eError, "is'not initialized.");
		return;
	}	

	OSAL_INT32 loc;
	pingNode *pingElem = OSAL_NULL;
	for(loc=OSAL_listGetHeadPos(pingResults); loc>=0 && loc < MAX_RTPP_COUNT; loc=OSAL_listGetNextPos(pingResults, loc))
	{
		pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
	  	if(!pingElem)
	  	{
			continue;
	  	}
		if(pingElem->pingSock){ 
			OSAL_async_select (ePING, pingElem->pingSock, 0, OSAL_NULL, OSAL_NULL);
			close(pingElem->pingSock);
		}
		if(pingElem->reportSock) 
			close(pingElem->reportSock);
		if(pingElem->respondSdkSock){ 
			OSAL_async_select (ePING, pingElem->respondSdkSock, 0, OSAL_NULL, OSAL_NULL);
			close(pingElem->respondSdkSock);
		}		
		OSAL_hashDestruct(pingElem->resultHash);
	}

	if(PingGlobalData.timerid_ping_rate) {
		OSAL_stimerStop(PingGlobalData.timerid_ping_rate);
		PingGlobalData.timerid_ping_rate = 0;
	}
	if(PingGlobalData.timerid_check_gw_active) {
		OSAL_stimerStop(PingGlobalData.timerid_check_gw_active);
		PingGlobalData.timerid_check_gw_active = 0;
	}
	if(PingGlobalData.timerid_ping_ip) {
		OSAL_stimerStop(PingGlobalData.timerid_ping_ip);
		PingGlobalData.timerid_ping_ip = 0;
	}

    OSAL_hashDestruct(ipHashTable);
	OSAL_listDestruct(pingResults);

}

OSAL_INT32 init_ping_cfg(OSAL_CHAR *buff, OSAL_INT32 lines)
{
	OSAL_CHAR *equ,*pch=NULL;
	OSAL_INT32 i = 0;
	OSAL_INT32 ip = 0;
	
	equ = strchr(buff, '=');
	if(!equ){
		return -1;
	}
	*equ = 0;
	equ++;
		
	if(!strcmp(buff, PING_LABEL_HOST_IP)){
		pch = strtok(equ, "/");
		while(NULL != pch) {
			strncpy(PingGlobalData.localip[i],pch,15);
			if(inet_pton(AF_INET,pch,&ip) != 1){
				OSAL_trace(ePING, eSys,"host ip %s is invalid", pch);
				exit(1);
			}
			OSAL_trace(ePING, eSys,"ping local host[%d]: %s", i,PingGlobalData.localip[i]);
			i++;
			if(i == MAX_RTPP_COUNT) break;
			pch = strtok(NULL, "/");
		}
		PingGlobalData.localipnum = i;
	}else if(!strcmp(buff, PING_LABEL_RTPC_IP)){
		pch = strtok(equ, "/");
		while(NULL != pch) {
			PingGlobalData.report_addr[i].sin_family = AF_INET;
			PingGlobalData.report_addr[i].sin_port = htons(9977);
			if(inet_pton(AF_INET,pch,&ip) != 1){
				OSAL_trace(ePING, eSys,"ping rtpc ip %s is invalid", pch);
				exit(1);
			}
			PingGlobalData.report_addr[i].sin_addr.s_addr = ip;
			OSAL_trace(ePING, eSys,"ping rtpc ip[%d]: %s", i,pch);
			i++; 
			if(i == MAX_RTPC_COUNT) break;
			pch = strtok(NULL, "/");
		}
		PingGlobalData.rtpc_num = i;
	}else if(!strcmp(buff, PING_LABEL_PING_RATE)){
		PingGlobalData.ping_rate = atoi(equ);
		OSAL_trace(ePING, eSys,"ping rate:%s",equ);
	}else if(!strcmp(buff, PING_LABEL_COLONY)){
		PingGlobalData.isEnable = atoi(equ);
		OSAL_trace(ePING, eSys,"ping enable:%s",equ);
	}
	return OSAL_OK;
}


static OSAL_BOOL compare_fd(OSAL_listElement element, void *param)
{
    if(!param || !element)
        return OSAL_FALSE;

	pingNode  *inside = (pingNode *)element;
    OSAL_UINT32 *fd     = (OSAL_UINT32 *)param;

    if(inside->pingSock == *fd)
        return OSAL_TRUE;
    else
        return OSAL_FALSE;
}

static void ping_process_in_imcp(int fd)
{
	OSAL_INT32 loc;
	pingNode *pingElem = OSAL_NULL;
	OSAL_CHAR recv_packet[PACKET_SIZE];
	struct sockaddr_in from_addr;
	int n;
	socklen_t fromlen = sizeof(from_addr);

	OSAL_listSetCompareFunc(pingResults, compare_fd);
	if((loc = OSAL_listGetPosByCompare(pingResults, 0, &fd, compare_fd)) >= 0)
	{	
		pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		if(!pingElem)
		{
			OSAL_trace(ePING, eError, "ping_process_in_imcp: get ping element error.");
			return;
		}
		
		n = recvfrom(pingElem->pingSock, recv_packet, PACKET_SIZE, 0,
			(struct sockaddr*)&from_addr, &fromlen);
		if(n < 0) {
			OSAL_trace(ePING, eWarn, "recv icmp err.");
			return;
		}
		if(unpack_process(recv_packet, n, &from_addr, pingElem) == OSAL_ERROR) {
			OSAL_trace(ePING, eWarn, "unpack icmp pack err");
			return;
		}			

	}
	else{
		OSAL_trace(ePING, eError,  "sock for handle ICMP err.");
		return;
	}

/*
	if(fd != PingGlobalData.ping_sock) {
		OSAL_trace(ePING, eError,  "sock for handle ICMP err.");
		return;
	}
	OSAL_CHAR recv_packet[PACKET_SIZE];
	struct sockaddr_in from_addr;
	int n;
	socklen_t fromlen = sizeof(from_addr);
	n = recvfrom(fd, recv_packet, PACKET_SIZE, 0,
		(struct sockaddr*)&from_addr, &fromlen);
	if(n < 0) {
		OSAL_trace(ePING, eWarn, "recv icmp err.");
		return;
	}
	if(unpack_process(recv_packet, n, &from_addr) == OSAL_ERROR) {
		OSAL_trace(ePING, eWarn, "unpack icmp pack err");
		return;
	}				
*/	
}


static OSAL_BOOL compare_rep_sdk_fd(OSAL_listElement element, void *param)
{
    if(!param || !element)
        return OSAL_FALSE;

	pingNode  *inside = (pingNode *)element;
    OSAL_UINT32 *fd     = (OSAL_UINT32 *)param;

    if(inside->respondSdkSock == *fd)
        return OSAL_TRUE;
    else
        return OSAL_FALSE;
}

static void respond_sdk_ping(int fd)
{
	OSAL_INT32 loc;
	pingNode *pingElem = OSAL_NULL;
	OSAL_CHAR recv_packet[PACKET_SIZE] = {0};
	struct sockaddr_in from_addr;
	int n;
	socklen_t fromlen = sizeof(from_addr);

	OSAL_listSetCompareFunc(pingResults, compare_fd);
	if((loc = OSAL_listGetPosByCompare(pingResults, 0, &fd, compare_rep_sdk_fd)) >= 0)
	{	
		pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		if(!pingElem)
		{
			OSAL_trace(ePING, eError, "ping_process_in_imcp: get ping element error.");
			return;
		}
		
		n = recvfrom(pingElem->respondSdkSock, recv_packet, PACKET_SIZE, 0,
			(struct sockaddr*)&from_addr, &fromlen);
		if(n < 0) {
			OSAL_trace(ePING, eWarn, "recv udp err.");
			return;
		}
		OSAL_trace(ePING, eInfo, "receive packet from %s:%d", inet_ntoa(from_addr.sin_addr), ntohs(from_addr.sin_port));
		OSAL_trace(ePING, eInfo, "receive packet: %s", recv_packet);

		if(strncmp(recv_packet, "ping", 4) == 0){
			sprintf(recv_packet, "pong from %.*s:%d", strlen(pingElem->rtppIp), pingElem->rtppIp, PingGlobalData.respond_sdk_port);
			sendto(pingElem->respondSdkSock, recv_packet, strlen(recv_packet), 0, (const struct sockaddr *)&from_addr, fromlen);
			return;
		}

		if(strncmp(recv_packet, "pong", 4) == 0){
			sendto(pingElem->respondSdkSock, recv_packet, n, 0, (const struct sockaddr *)&from_addr, fromlen);
			return;
		}			

	}
	else{
		OSAL_trace(ePING, eError,  "sock for handle ICMP err.");
		return;
	}

}


/*
static void control_rtpp_ips(OSAL_msgHdr *pMsg)
{	
	OSAL_INT32 i = 0;
	switch(pMsg->param)
	{
		case eUPDATE_IPS:
		{	
			rtpc_no = get_rtpc_num((char*)pMsg->pContent);
			OSAL_CHAR *pch = strchr((char*)pMsg->pContent, '/');
			OSAL_CHAR *pch_bak = (char*)pMsg->pContent;
			//memset(&PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT], 0, MAX_RTPP_COUNT*sizeof(RtppProperty));
			while(pch) {	
				if(strlen(PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].ip))
				{
					if(PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].noPing == 0)	
						update_other_ping_flag(rtpc_no, PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].ip);			
					memset(&PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i], 0, sizeof(RtppProperty));
				}
				strncpy(PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].ip, pch_bak, pch-pch_bak);
				pch_bak = ++pch;
				pch = strchr(pch, '/');
				i++;
			}
			if(pch_bak && strlen(pch_bak)) {
				if(strlen(PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].ip))
				{
					if(PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].noPing == 0)	
						update_other_ping_flag(rtpc_no, PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].ip);			
					memset(&PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i], 0, sizeof(RtppProperty));
				}
				strncpy(PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].ip, pch_bak, strlen(pch_bak));
				i++;
			}
			memset(&PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i], 0, 
					(MAX_RTPP_COUNT-i)*sizeof(RtppProperty));
			memset(&pProbe_results[rtpc_no*MAX_RTPP_COUNT], 0, MAX_RTPP_COUNT*sizeof(ping_probe_result_T));				
		}
		break;
		case eDELETE_IPS:
			break;
		case eCLEAR_IPS:
			{
				rtpc_no = get_rtpc_num((char*)pMsg->pContent);
				for(i=0; i<MAX_RTPP_COUNT; i++) {
					if(strlen(PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].ip))
					{
						if(PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].noPing == 0)	
							update_other_ping_flag(rtpc_no, PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i].ip);
						memset(&PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT+i], 0, sizeof(RtppProperty));
					}
					else
						break;
				}
			}
			break;
		default:
			OSAL_trace(ePING, eWarn, "recv unkown msg param.");
			break;	
	}
}


static void control_rtpp_ips(OSAL_msgHdr *pMsg)
{
	ipInfo_t	ipInfo;
	OSAL_CHAR	keyBuff[IP_LEN];

	switch(pMsg->param)
	{
		case eUPDATE_IPS:
		{	
			OSAL_CHAR *pch = strchr((char*)pMsg->pContent, '/');
			OSAL_CHAR *pch_bak = (char*)pMsg->pContent;
			//memset(&PingGlobalData.pRTPPs[rtpc_no*MAX_RTPP_COUNT], 0, MAX_RTPP_COUNT*sizeof(RtppProperty));
			while(pch) 
			{
				memset(keyBuff, 0, sizeof(ipInfo_t));
				strncpy(keyBuff, pch, sizeof(keyBuff));	

				if(OSAL_NULL == find_elements_by_ip(ipHashTable, keyBuff))				
				{//add ip to ipHashTable  				
					memset(&ipInfo, 0, sizeof(ipInfo_t));
					ipInfo.iptype = RTPP_IP;				
					ipInfo.valid = OSAL_TRUE;
					ipInfo.ttl = time(NULL);
					
					if ( OSAL_NULL == OSAL_hashAdd(ipHashTable, keyBuff, &ipInfo, OSAL_FALSE) )
					{
					    OSAL_trace(ePING, eError,  "Add gateway ip to hash table failed.");
					}			
				}
				
				pch_bak = ++pch;
				pch = strchr(pch, '/');
			}
			if(pch_bak && strlen(pch_bak))
			{			
				memset(keyBuff, 0, sizeof(ipInfo_t));
				strncpy(keyBuff, pch, sizeof(keyBuff));
				ipInfo.iptype = GW_IP;
				ipInfo.valid = OSAL_TRUE;			
				ipInfo.ttl = time(NULL);
				
				if(OSAL_NULL == find_elements_by_ip(ipHashTable, keyBuff))
				{//add last ip to ipHashTable  
					memset(&ipInfo, 0, sizeof(ipInfo_t));
					strncpy(ipInfo.ip, pch, sizeof(ipInfo.ip));
					ipInfo.iptype = GW_IP;
					ipInfo.valid = OSAL_TRUE;
					if ( OSAL_NULL == OSAL_hashAdd(ipHashTable, keyBuff, &ipInfo, OSAL_FALSE) )
					{
					    OSAL_trace(ePING, eError,  "Add gateway ip to hash table failed.");
					}
				}
			}	
		}
		break;
		
		case eDELETE_IPS:
			break;
			
		case eCLEAR_IPS:
			break;
			
		default:
			OSAL_trace(ePING, eWarn, "recv unkown msg param.");
			break;	
	}

}
*/

static void control_ips(OSAL_msgHdr *pMsg, ip_type type)
{
	ipInfo_t	ipInfo;
	OSAL_CHAR	keyBuff[IP_LEN];
	ipInfo_t *pHash = NULL;

	switch(pMsg->param)
	{
		case eUPDATE_IPS:
		{	
			OSAL_CHAR *pch = strchr((char*)pMsg->pContent, '/');
			OSAL_CHAR *pch_bak = (char*)pMsg->pContent;
			OSAL_trace(ePING, eDebug, "receive iplist from RTPP module,which content is %s .", pch_bak);
			while(pch) 
			{
				memset(keyBuff, 0, sizeof(keyBuff));				
				strncpy(keyBuff, pch_bak, pch-pch_bak);
				keyBuff[IP_LEN-1] = '\0';
				OSAL_trace(ePING, eDebug, "control_ips: hash key = %s", keyBuff);

				if(OSAL_NULL == (pHash = OSAL_hashElemFind(ipHashTable, keyBuff)))				
				{//add ip to ipHashTable  				
					memset(&ipInfo, 0, sizeof(ipInfo_t));
					strcpy(ipInfo.ip, keyBuff);
					ipInfo.iptype = type;				
					ipInfo.ttl = time(NULL);
					
					if ( OSAL_NULL == OSAL_hashAdd(ipHashTable, keyBuff, &ipInfo, OSAL_FALSE) )
					{
					    OSAL_trace(ePING, eError,  "add gw %s to hash table failed.", ipInfo.ip);
					}
					else
						OSAL_trace(ePING, eDebug, "add gw: %s to ipHashTable.", ipInfo.ip);
				}
				else{
					pHash->ttl = time(NULL);
					OSAL_trace(ePING, eDebug, "update gw's ttl: %s in ipHashTable.", pHash->ip);
				}
				
				pch_bak = ++pch;
				pch = strchr(pch, '/');
			}
			if(pch_bak && strlen(pch_bak))
			{			
				memset(keyBuff, 0, sizeof(keyBuff));
				strncpy(keyBuff, pch_bak, OSAL_strnLen(pch_bak, IP_LEN));
				keyBuff[IP_LEN-1] = '\0';
				OSAL_trace(ePING, eDebug, "control_ips: hash key = %s", keyBuff);

				if(OSAL_NULL == (pHash = OSAL_hashElemFind(ipHashTable, keyBuff)))
				{//add last ip to ipHashTable  
					memset(&ipInfo, 0, sizeof(ipInfo_t));
					strcpy(ipInfo.ip, keyBuff);
					ipInfo.iptype = type;
					ipInfo.ttl = time(NULL);

					if ( OSAL_NULL == OSAL_hashAdd(ipHashTable, keyBuff, &ipInfo, OSAL_FALSE) )
					{
					    OSAL_trace(ePING, eError,  "add gw %s to hash table failed.", ipInfo.ip);
					}					
					else
						OSAL_trace(ePING, eDebug, "add gw: %s to ipHashTable.", ipInfo.ip);
				}
				else{
					pHash->ttl = time(NULL);
					OSAL_trace(ePING, eDebug, "update gw's ttl: %s in ipHashTable.", pHash->ip);
				}
			}	
		}
		break;
		
		case eDELETE_IPS:
			break;
			
		case eCLEAR_IPS:
			break;
			
		default:
			OSAL_trace(ePING, eWarn, "recv unkown msg param.");
			break;	
	}

}


static void control_ping_able(OSAL_msgHdr *pMsg)
{
	switch(pMsg->param)
	{
		case eENABLE:
			if(PingGlobalData.isEnable == OSAL_TRUE) {
				printf("\tRtpc colony is open areadly.\n");
				return;
			}
			//start_timer_outICMP();
			ping_out_imcp();
			PingGlobalData.isEnable = OSAL_TRUE;
			refine_cfg_entry(CONFIG_FILE, "PING_COLONY", "on");
			break;
		case eDISABLE:
			if(PingGlobalData.isEnable == OSAL_FALSE) {
				printf("\tRtpc colony is closed areadly.\n");
				return;
			}
			//OSAL_stimerStop(PingGlobalData.timerid_ping_rate);
			PingGlobalData.isEnable = OSAL_FALSE;	
			refine_cfg_entry(CONFIG_FILE, "PING_COLONY", "off");
			break;
		default:
			OSAL_trace(ePING, eWarn, "Invalid msg type.");
			break;
	}
}

static void send_heartbeat_to_rtpc()
{
	OSAL_INT32 loc = 0;
	pingNode *pingElem = OSAL_NULL;
	OSAL_INT32 k = 0;
	OSAL_CHAR heart_buffer[32] = {0};
	OSAL_INT32 notify = 0;
	/*
	if(PingGlobalData.hb_times % 11 == 10){
		//sprintf(heart_buffer, "%s %d", "H heartbeat", rtpp_hash_tbl.used);
		PingGlobalData.hb_times = 0;
		notify = 1;
	}
	else
		strcpy(heart_buffer, "H heartbeat");*/
	
	if ((loc=OSAL_listGetHeadPos(pingResults))>=0)
	{
		pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		if(!pingElem)
		{
			OSAL_trace(ePING, eError, "commit_results: get ping element error.");
			return;
		}

		for (; loc>=0 && loc < MAX_RTPP_COUNT; loc=OSAL_listGetNextPos(pingResults, loc))
		{
			pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
			if(!pingElem)
			{
				continue;
			}

			//if(notify)
			//{
				sprintf(heart_buffer, "%s %u %d", "H heartbeat",rtpp_hash_tbl.used,table[loc].used);
			//}
			
			for(k = 0; k < PingGlobalData.rtpc_num; k++)
			{
				//send
				if(sendto(pingElem->reportSock, heart_buffer, OSAL_strnLen(heart_buffer, 32), 0, 
						(struct sockaddr*)&PingGlobalData.report_addr[k], sizeof(struct sockaddr)) < 0){
					OSAL_trace(ePING, eError, "send heartbeat(%s) from rtpp(%s) to rtpc(%s) err %s.", 
							heart_buffer, pingElem->rtppIp, inet_ntoa(PingGlobalData.report_addr[k].sin_addr),strerror(errno));
				}else{
					OSAL_trace(ePING, eInfo, "send heartbeat(%s) from rtpp(%s) to rtpc(%s) ok.", heart_buffer, pingElem->rtppIp,
							inet_ntoa(PingGlobalData.report_addr[k].sin_addr));
				}
			}					
		}
	}
	else
	{		
		OSAL_trace(ePING, eError, "send_heartbeat_to_rtpc: pingResults list is emply.");
		return;
	}
	
}


static void ping_handle_timer (OSAL_timerMsgHdrT *timerHdr)
{
	switch (timerHdr->param1)
	{
	  	case PING_TMR_PINGRATE:

			if(PingGlobalData.isEnable)
			{			
				ping_out_imcp();          //send icmp to all rtpp
			}
			break;
			 
		case PING_TMR_REPORTRATE:

			commit_results();         //report results to rtpc
			
			OSAL_trace(ePING, eInfo, "ping_handle_timer: start timer to start next ping round.");
			start_timer_outICMP();
			break;

		case PING_TMR_CHECKACTIVE:

			update_gw_list();         //update gw list according to the timestamp
			break;

		case PING_TMR_PINGIP:

			OSAL_trace(ePING, eInfo, "ping_handle_timer: start ping times: %d. ", PingGlobalData.ping_times + 1);			 
			ping_lauch_action();         //lauch ping test
			PingGlobalData.ping_times++ ;
			if(PingGlobalData.ping_times >= 10)
		 	{
				if(PingGlobalData.timerid_ping_ip != OSAL_INVALID_TIMER_ID) {
					OSAL_stimerStop(PingGlobalData.timerid_ping_ip);
					PingGlobalData.timerid_ping_ip = OSAL_INVALID_TIMER_ID;
				}
				
				PingGlobalData.ping_times = 0;

				OSAL_trace(ePING, eInfo, "ping_handle_timer: start timer to commit results to rtpc.");
				start_timer_ciResults();
			}			 	
			break;

		case PING_TMR_HEARTBEAT:

			PingGlobalData.hb_times++ ;	
			send_heartbeat_to_rtpc();		  //send heartbeat to rtpc
			break;
			 
		default:
			OSAL_trace(eRTPP, eWarn, "Invalid PING Module operate type");
			break;
			
	}
}

unsigned short cal_chksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
	while(nleft > 1) {            
		sum += *w++;
		nleft -=2;
	}
	if(nleft == 1) {
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;
	}
	sum = (sum>>16) + (sum&0xffff);
	sum += (sum>>16);
	answer=~sum;
	
	return answer;
}

 static OSAL_INT32 pack(int n, OSAL_CHAR* buff, icmpType type, struct in_addr *to_ip)
{
	int packsize;
	struct icmp *icmp;
	struct timeval *tval;
	OSAL_UINT8 *p;
	
	icmp = (struct icmp*)buff;
	if(GW_IP == type)
		icmp->icmp_type = ICMP_ECHO;
	else //RTPP_IP
		icmp->icmp_type = ICMP_PROBE_T;
	icmp->icmp_code = 0;
	icmp->icmp_seq = (unsigned short)n;
	icmp->icmp_id = rtpp_pid;
	//packsize = 8+DATA_LEN;
	packsize = sizeof(struct icmphdr) + sizeof(struct timeval) + sizeof(struct in_addr);
	p = icmp->icmp_data;
	tval= (struct timeval *)p;	
	gettimeofday(tval, NULL);
	p += sizeof(struct timeval);
	memcpy(p, to_ip, sizeof(struct in_addr));
	icmp->icmp_cksum = cal_chksum((unsigned short *)icmp, packsize);

	return packsize;	
}

void tv_sub(struct timeval *out, struct timeval* in)
{
	if( (out->tv_usec-=in->tv_usec)<0) {
		--out->tv_sec;
		out->tv_usec+=1000000;
	}
	out->tv_sec-=in->tv_sec;
}

static OSAL_INT32 unpack_process(OSAL_CHAR *buff, int n, struct sockaddr_in* from, pingNode *pingElem)
{
	OSAL_INT32  iphdrlen;
	struct ip *ip;
	struct icmp *icmp;

	if (n < sizeof(struct ip)) {
		OSAL_trace(ePING, eWarn, "unpaking a illegality IP packet.");
		return OSAL_ERROR;
	}
	
	ip = (struct ip*)buff;
	iphdrlen = ip->ip_hl<<2;
	icmp = (struct icmp*)(buff+iphdrlen);
	n = n-iphdrlen;

	if(n < sizeof(struct icmphdr)) {
		OSAL_trace(ePING, eWarn, "unpaking a illegality ICMP.");
		return OSAL_ERROR;
	}
	
 	if(icmp->icmp_type == ICMP_PROBE_T)
	{	
		OSAL_trace(ePING, eInfo, "unpack_process: reply for other ping from %s.", inet_ntoa(from->sin_addr));
		icmp->icmp_type = ICMP_REPLY_T;
		sendto(pingElem->pingSock, icmp, n, 0, 
			(struct sockaddr*)from, sizeof(struct sockaddr));
	}
 	else if(icmp->icmp_type == ICMP_SHELL_PROBE_T)
	{	
		OSAL_trace(ePING, eInfo, "unpack_process: reply for a rtpp's shell ping");
		icmp->icmp_type = ICMP_SHELL_REPLY_T;
		sendto(pingElem->pingSock, icmp, n, 0, 
			(struct sockaddr*)from, sizeof(struct sockaddr));
	}	
	else if((icmp->icmp_type == ICMP_REPLY_T) || (icmp->icmp_type == ICMP_ECHOREPLY))
	{
		if(icmp->icmp_id != rtpp_pid) 
			return OSAL_ERR_UNKOWN;		
		struct timeval tvrecv;
		struct timeval *tvsend;
		struct in_addr to_ip;
		OSAL_CHAR toip_str[32];
		OSAL_UINT32 rtt;
		gettimeofday(&tvrecv, OSAL_NULL);
		tvsend = (struct timeval*)icmp->icmp_data;
		tv_sub(&tvrecv, tvsend);
		rtt=tvrecv.tv_sec*1000+tvrecv.tv_usec/1000;	
		memcpy(&to_ip, icmp->icmp_data + sizeof(struct timeval), sizeof(struct in_addr));

		OSAL_trace(ePING, eInfo, "unpack_process: get reply from %s to complete result", inet_ntoa(from->sin_addr));
		
		if (to_ip.s_addr != from->sin_addr.s_addr) {
			OSAL_trace(ePING, eInfo, "from ip isn't match to ip in REPLY packet, from ip %s, to ip %s",
				inet_ntoa(from->sin_addr), inet_ntop(AF_INET, &to_ip, toip_str, 32));
			complete_result(inet_ntoa(to_ip), rtt, pingElem);
		}else {
			complete_result(inet_ntoa(from->sin_addr), rtt, pingElem);
		}
	}
	else {
		//OSAL_trace(ePING, eInfo, "recv isn't our define ICMP type(%d).", icmp->icmp_type);
		return OSAL_ERR_UNKOWN;
	}
	
	return OSAL_OK;
}

static  void ping_out_imcp()
{	
	OSAL_trace(ePING, eInfo, "ping_out_imcp: start timer to pingIp.");
	start_timer_pingIp(); 
	
	//start timer for report to rtpc
	//OSAL_trace(ePING, eInfo, "ping_out_imcp: start timer to ciResults.");
	//start_timer_ciResults();
}

void *generate_results(OSAL_HHASH hHash, void  *elem, void *param)
{	
	OSAL_INT32 i;
	OSAL_INT32 delay =  3000;
	OSAL_INT32 delayTotal =  0;
	OSAL_INT32 lost  =  100;	
	OSAL_CHAR result_buff[32] = {0};	
	ipInfo_t *ip_str = NULL;
	if(OSAL_NULL== param || OSAL_NULL == elem)
    {
    	return param;
    }
	
	//OSAL_CHAR *buff = (OSAL_CHAR *)param;	
	ip_str = (ipInfo_t*)elem;	
	for(i=0;i<ip_str->received;i++)
	{
	
		delayTotal += ip_str->delay[i];
	}
	if(ip_str->sended > 0)
	{	
		if(ip_str->received == 0)
			delay = 3000;
		else
			delay = delayTotal / ip_str->received;
		lost  = (ip_str->sended - ip_str->received) * 100 / ip_str->sended ;		
	}
	if(ip_str->iptype == GW_IP)
	{	
		sprintf(result_buff, "%s,%d,%d ", ip_str->ip, delay, lost);
	}
	else
	{
		sprintf(result_buff, "%s:%d:%d ", ip_str->ip, delay, lost);
	}

	//if(strlen(buff)==0)
		//strcat(buff, "K");
	
	strcat(param, result_buff);

	return param;

}

static void commit_results()
{
#define MAX_SEND_BYTES 4096
	OSAL_INT32 loc;
	pingNode *pingElem = OSAL_NULL;
	OSAL_INT32 k;
	OSAL_CHAR *commit_buff = OSAL_NULL;
	OSAL_INT32 i;
	OSAL_CHAR *p = OSAL_NULL;
	OSAL_CHAR *q = OSAL_NULL;
	OSAL_CHAR temp[MAX_SEND_BYTES];
	memset(temp, 0, sizeof(temp));
	OSAL_trace(ePING, eInfo, "start to commit results.");
	if ((loc=OSAL_listGetHeadPos(pingResults))>=0)
	{
		pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		if(!pingElem)
		{
			OSAL_trace(ePING, eError, "commit_results: get ping element error.");
			return;
		}

		for (; loc>=0 && loc < MAX_RTPP_COUNT; loc=OSAL_listGetNextPos(pingResults, loc))
		{
			pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		  	if(!pingElem)
		  	{
				continue;
		  	}
			commit_buff = (OSAL_CHAR *)osal_quick_allocate(MAX_IP_NUM * (IP_LEN + 10), 
					DEFAULT_FLAGS | MEMF_ZERO_MEMORY , MAGIC_NUMBER('P','I','G','r'), NULL);
			if(OSAL_NULL == commit_buff)
			{
				OSAL_trace(ePING, eError,  "malloc failed.");
				return ;
			}
			// gennerate results
			OSAL_hashDoAll(pingElem->resultHash, generate_results, commit_buff);

			//commit last result to rtpc			
			for(k = 0; k < PingGlobalData.rtpc_num; k++)
			{
				q = commit_buff;
				if(strlen(q) == 0){
					strcpy(temp, "K 0");
					OSAL_trace(ePING, eInfo, "commit from %s to rtpc(%s):%s.", pingElem->rtppIp,
											inet_ntoa(PingGlobalData.report_addr[k].sin_addr), temp);
					if(sendto(pingElem->reportSock, temp, OSAL_strnLen(temp, MAX_SEND_BYTES), 0, 
												(struct sockaddr*)&PingGlobalData.report_addr[k], sizeof(struct sockaddr)) < 0)
						OSAL_trace(ePING, eWarn, "commit last result from %s to rtpc err.", pingElem->rtppIp);
					
                	memset(temp , 0, sizeof(temp));
				}

				while(strlen(q) > 0)
        		{
                	strcat(temp, "K ");
                	for(i=0;i<150;i++)
                	{
                        if((p = strchr(q, ' ')) != NULL)
                        {
                            p++;
                            strncat(temp, q, p - q);
                            q = p;
                        }
                        else
                        {
                            strcat(temp, q);
                            q = "";
                            break;
                        }
                	}
					//send result to rtpc.
					if(sendto(pingElem->reportSock, temp, OSAL_strnLen(temp, MAX_SEND_BYTES), 0, 
												(struct sockaddr*)&PingGlobalData.report_addr[k], sizeof(struct sockaddr)) < 0)
						OSAL_trace(ePING, eWarn, "commit last result from %s to rtpc err.", pingElem->rtppIp);
					else
						OSAL_trace(ePING, eInfo, "commit from %s to rtpc(%s):%s.", pingElem->rtppIp,
												inet_ntoa(PingGlobalData.report_addr[k].sin_addr), temp);
					
                	memset(temp , 0, sizeof(temp));
				}
				
			}

			if(commit_buff)
				osal_free(commit_buff);

			//clear the result hash	
			reset_result_hash(pingElem->resultHash);

		}		
					
	}
	else
	{		
		OSAL_trace(ePING, eError, "commit_results: ping results list is emply.");
		return;
	}
	
	PingGlobalData.timerid_report_rate = -1;


/*
	OSAL_INT32 loc;
	pingNode *pingElem = OSAL_NULL;
	OSAL_INT32 k;
	OSAL_CHAR *commit_buff = OSAL_NULL;
	OSAL_trace(ePING, eInfo, "commit_results : commit results.");
	if ((loc=OSAL_listGetHeadPos(pingResults))>=0)
	{
		pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		if(!pingElem)
		{
			OSAL_trace(ePING, eError, "commit_results: get ping element error.");
			return;
		}

		for (; loc>=0 && loc < MAX_RTPP; loc=OSAL_listGetNextPos(pingResults, loc))
		{
			pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		  	if(!pingElem)
		  	{
				continue;
		  	}
			commit_buff = (OSAL_CHAR *)osal_quick_allocate(MAX_IP_NUM * (IP_LEN + 10), 
					DEFAULT_FLAGS | MEMF_ZERO_MEMORY , MAGIC_NUMBER('P','I','G','r'), NULL);
			if(OSAL_NULL == commit_buff)
			{
				OSAL_trace(ePING, eError,  "malloc failed.");
				return ;
			}
			strcat(commit_buff, "K");
			OSAL_hashDoAll(pingElem->resultHash, generate_results, commit_buff);
			if(strlen(commit_buff) == 1)
				strcpy(commit_buff, "K 0");

			//commit last result to rtpc			
			for(k = 0; k < PingGlobalData.rtpc_num; k++)
			{
				OSAL_trace(ePING, eInfo, "commit from %s to rtpc(%s):%s.", pingElem->rtppIp,
							inet_ntoa(PingGlobalData.report_addr[k].sin_addr), commit_buff);
				//send
				if(sendto(pingElem->reportSock, commit_buff, OSAL_strnLen(commit_buff, MAX_IP_NUM * (IP_LEN + 10)), 0, 
						(struct sockaddr*)&PingGlobalData.report_addr[k], sizeof(struct sockaddr)) < 0)
					OSAL_trace(ePING, eWarn, "commit last result from %s to rtpc err.", pingElem->rtppIp);
			}		
			if(commit_buff){
				osal_free(commit_buff);
			}
			
			reset_result_hash(pingElem->resultHash);
			
		}
	}
	else
	{		
		OSAL_trace(ePING, eError, "commit_results: ping results list is emply.");
		return;
	}
	
	PingGlobalData.timerid_report_rate = -1;
*/
}

static void complete_result(OSAL_CHAR* ip, OSAL_UINT32 timestamp, pingNode *pingElem)
{
	ipInfo_t *pHash = NULL;
	if(!ip)
		return;

	OSAL_CHAR pHashKey[IP_LEN];
	memset(pHashKey, 0, sizeof(pHashKey));
	strncpy(pHashKey, ip, OSAL_strnLen(ip, IP_LEN));
	pHashKey[IP_LEN-1] = '\0';	
	OSAL_trace(ePING, eDebug, "hash key = %s", pHashKey);
	
	if(OSAL_NULL != (pHash = (ipInfo_t *)OSAL_hashElemFind(pingElem->resultHash, pHashKey)))
	{
		if(pHash->received < PING_REPEAT * 2){
			pHash->delay[pHash->received++] = timestamp;	
			OSAL_trace(ePING, eInfo, "complete_result: pHash->sended is %d, pHash->received is %d", pHash->sended, pHash->received);
			OSAL_trace(ePING, eInfo, "complete_result: delay is %d", timestamp);
		}
	}
	else
		OSAL_trace(ePING, eWarn, "%s is not found in the hashtable", ip);	

}

static void start_timer_send_heartbeat()
 {
	 OSAL_timerMsgHdrT timerInfo_heartbeat;
	 timerInfo_heartbeat.moduleId = ePING;
	 timerInfo_heartbeat.timerMsgType = eOsalSysMsgIdTimer;
	 timerInfo_heartbeat.param1 = PING_TMR_HEARTBEAT;
#ifdef USE_SYN_TIMER
	 PingGlobalData.timerid_heart_beat = OSAL_stimerStart (&timerInfo_heartbeat, 1*1000);	// 3s
#else
	 PingGlobalData.timerid_heart_beat = OSAL_timerStart (&timerInfo_heartbeat, 1*1000); 
#endif
 }

static void start_timer_outICMP()
{
	OSAL_timerMsgHdrT timerInfo_pingrate;
	timerInfo_pingrate.moduleId = ePING;
	timerInfo_pingrate.timerMsgType = eOsalSysMsgIdTimer;
	timerInfo_pingrate.param1 = PING_TMR_PINGRATE;
#ifdef USE_SYN_TIMER
	PingGlobalData.timerid_ping_rate = OSAL_stimerUseOneTime (&timerInfo_pingrate, PingGlobalData.ping_rate*1000);  // 15s
#else
	PingGlobalData.timerid_ping_rate = OSAL_timerUseOneTime (&timerInfo_pingrate, PingGlobalData.ping_rate*1000); 
#endif	
}

static void start_timer_ciResults()
{
	OSAL_timerMsgHdrT timerInfo_reportrate;
	memset (&timerInfo_reportrate, 0, sizeof(OSAL_timerMsgHdrT));
	timerInfo_reportrate.moduleId = ePING;
	timerInfo_reportrate.timerMsgType = eOsalSysMsgIdTimer;
	timerInfo_reportrate.param1 = PING_TMR_REPORTRATE;
#ifdef USE_SYN_TIMER
	PingGlobalData.timerid_report_rate = OSAL_stimerUseOneTime(&timerInfo_reportrate, 5*1000);  //5s
#else
	PingGlobalData.timerid_report_rate = OSAL_timerUseOneTime(&timerInfo_reportrate, 5*1000);  //5s
#endif
	
}

static void start_timer_checkGwActive()
{
	OSAL_timerMsgHdrT timerInfo_checkactive;
	memset (&timerInfo_checkactive, 0, sizeof(OSAL_timerMsgHdrT));
	timerInfo_checkactive.moduleId = ePING;
	timerInfo_checkactive.timerMsgType = eOsalSysMsgIdTimer;
	timerInfo_checkactive.param1 = PING_TMR_CHECKACTIVE;
#ifdef USE_SYN_TIMER
	PingGlobalData.timerid_check_gw_active = OSAL_stimerStart(&timerInfo_checkactive, 30*60*1000);  //30 minutes
#else
	PingGlobalData.timerid_check_gw_active = OSAL_timerStart(&timerInfo_checkactive, 30*60*1000);  //30 minutes
#endif

}


static void start_timer_pingIp()
{
	OSAL_timerMsgHdrT timerInfo_pingip;
	memset (&timerInfo_pingip, 0, sizeof(OSAL_timerMsgHdrT));
	timerInfo_pingip.moduleId = ePING;
	timerInfo_pingip.timerMsgType = eOsalSysMsgIdTimer;
	timerInfo_pingip.param1 = PING_TMR_PINGIP;
#ifdef USE_SYN_TIMER
	PingGlobalData.timerid_ping_ip = OSAL_stimerStart(&timerInfo_pingip, 1000);  //1s
#else
	PingGlobalData.timerid_ping_ip = OSAL_timerStart(&timerInfo_pingip, 1000);	//1s
#endif
	
}


void *check_ttl(OSAL_HHASH hHash, void  *elem, void *param)
{
	unsigned long offset = 0;
	time_t t = time(NULL);
	ipInfo_t *ip_str = NULL;
	if(NULL == elem)
    {
    	return param;
    }

	ip_str = (ipInfo_t*)elem;
	OSAL_CHAR keyBuff[IP_LEN] = {0};
	memcpy(keyBuff, ip_str->ip, sizeof(keyBuff) - 1);
	
	offset = t - ip_str->ttl;
	if((ip_str->iptype == GW_IP) && (offset >= MAX_TTL_TIME))
	{
		memset(ip_str, 0, sizeof(ipInfo_t));
		OSAL_hashElemDelete(ipHashTable, keyBuff, ip_str);
	}

	return NULL;
}


static void update_gw_list()
{
	
	OSAL_hashDoAll(ipHashTable, check_ttl, NULL);
}

void *reset_info(OSAL_HHASH hHash, void  *elem, void *param)
{
	ipInfo_t *ip_str = NULL;
	if(NULL == elem || NULL == param)
    {
    	return NULL;
    }

	ip_str = (ipInfo_t*)elem;
	OSAL_HHASH hash = (OSAL_HHASH)param;
	
	OSAL_CHAR keyBuff[IP_LEN] = {0};
	memcpy(keyBuff, ip_str->ip, sizeof(keyBuff) - 1);

	memset(ip_str, 0, sizeof(ipInfo_t));
	OSAL_hashElemDelete(hash, keyBuff, ip_str);

	return param;

/*
	ipInfo_t *ip_str = NULL;
	if(NULL == elem)
    {
    	return elem;
    }

	ip_str = (ipInfo_t*)elem;
	//memset(ip_str->ip , 0, sizeof(ip_str->ip));
	memset(ip_str->delay , 0, sizeof(ip_str->delay));
	ip_str->sended = 0;
	ip_str->received = 0;

	return NULL;
*/
}


static void reset_result_hash(OSAL_HHASH hash)
{
	OSAL_hashDoAll(hash, reset_info, hash); 

/*
	OSAL_INT32 loc;
	pingNode *pingElem = OSAL_NULL;

	if ((loc=OSAL_listGetHeadPos(pingResults))>=0)
	{
		pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		if(!pingElem)
		{
			OSAL_trace(ePING, eError, "ping_lauch_action: get ping element error.");
			return;
		}		
	
		for (; loc>=0 && loc < MAX_RTPP; loc=OSAL_listGetNextPos(pingResults, loc))
		{
			pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		  	if(!pingElem)
		  	{
				continue;
		  	}
			
			OSAL_hashDoAll(pingElem->resultHash, reset_info, NULL);			
		}
	}
	else
	{		
		OSAL_trace(ePING, eError, "reset_ip_info: ping results list is emply.");
		return;
	}
*/	
}

void *ping_test(OSAL_HHASH hHash, void  *elem, void *param)
{
	if(NULL == elem || NULL == param)
    {
    	return OSAL_NULL;
    }

	int i;
	ipInfo_t *ip_str = (ipInfo_t*)elem;		
	pingNode *pingElem = (pingNode *)param;
	
	if(memcmp(pingElem->rtppIp, ip_str->ip, sizeof(pingElem->rtppIp)) == 0)
		return (pingNode *)param;

	OSAL_INT32 pack_len;
	OSAL_INT32 ret;
	OSAL_CHAR send_pack[PACKET_SIZE];	
	//memset(send_pack, 0, sizeof(send_pack));
	
	ipInfo_t	ipInfo;
	ipInfo_t *pHash = NULL;
	OSAL_CHAR	keyBuff[IP_LEN];				
	memset(keyBuff, 0, sizeof(keyBuff));
	strncpy(keyBuff, ip_str->ip, OSAL_strnLen(ip_str->ip, IP_LEN));
	keyBuff[IP_LEN-1] = '\0';
	OSAL_trace(ePING, eDebug,  "hash key = %s", keyBuff);
	
	struct sockaddr_in dest_addr;
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	in_addr_t inaddr = inet_addr(ip_str->ip);
	memcpy((char*)&dest_addr.sin_addr, (char*)&inaddr, sizeof(inaddr));	

	for(i=0;i<2;i++)
	{
		memset(send_pack, 0, sizeof(send_pack));	
		pack_len = pack(PingGlobalData.ping_times * 2 + i + 1, send_pack, ip_str->iptype, (struct in_addr*)&inaddr);

		if((ret = sendto(pingElem->pingSock, send_pack, pack_len, 0, 
			(struct sockaddr*)&dest_addr, sizeof(dest_addr))) !=  pack_len)
		{
			OSAL_trace(ePING, eError, "send %d prober ICMP to %s err,need(%d)but(%d) %s", PingGlobalData.ping_times + 1, ip_str->ip,pack_len,ret,strerror(errno));
		}
		else
		{
			if(OSAL_NULL == (pHash = OSAL_hashElemFind(pingElem->resultHash, keyBuff)))				
			{  				
				memset(&ipInfo, 0, sizeof(ipInfo_t));
				strcpy(ipInfo.ip, keyBuff);		
				ipInfo.iptype = ip_str->iptype;
				ipInfo.sended++;
				
				OSAL_trace(ePING, eInfo, "send %dth prober ICMP from %s to %s ", ipInfo.sended, pingElem->rtppIp, ip_str->ip);
				
				if ( OSAL_NULL == OSAL_hashAdd(pingElem->resultHash, keyBuff, &ipInfo, OSAL_FALSE) )
				{
				    OSAL_trace(ePING, eError,  "Add ip: %s to ping result hash table failed.", ipInfo.ip);
				}			
				else
					OSAL_trace(ePING, eDebug, "add ip: %s to resultHash table.", ipInfo.ip);
				
			}
			else{
				pHash->sended++;	
				OSAL_trace(ePING, eInfo, "send %dth prober ICMP from %s to %s ", pHash->sended, pingElem->rtppIp, ip_str->ip);
			}
		}
	}
	
	return (pingNode *)param;
	
/*
	OSAL_INT32 pack_len;
	OSAL_CHAR send_pack[PACKET_SIZE];	
	memset(send_pack, 0, sizeof(send_pack));
	if(NULL == elem || NULL == param)
	{
		return OSAL_NULL;
	}
	ipInfo_t *ip_str = (ipInfo_t*)elem; 
	
	struct sockaddr_in dest_addr;
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	unsigned long inaddr = inet_addr(ip_str->ip);
	memcpy((char*)&dest_addr.sin_addr, (char*)&inaddr, sizeof(inaddr)); 
	
	pack_len = pack(ip_str->sended + 1, send_pack, ip_str->iptype);

	if(sendto(PingGlobalData.ping_sock, send_pack, pack_len, 0, 
		(struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0)
	{
		OSAL_trace(ePING, eWarn, "send %dth prober ICMP to %s err", ip_str->sended, ip_str->ip);
	}
	ip_str->sended++;
	
	OSAL_trace(ePING, eInfo, "ping_test: ip_str->sended is %d", ip_str->sended);
	
	return OSAL_NULL;
*/
}


static void ping_lauch_action()
{
	OSAL_INT32 loc;
	pingNode *pingElem = OSAL_NULL;
	OSAL_trace(ePING, eInfo, "ping_lauch_action: ping all ip.");
	if ((loc=OSAL_listGetHeadPos(pingResults))>=0)
	{
		pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		if(!pingElem)
		{
			OSAL_trace(ePING, eError, "ping_lauch_action: get ping element error.");
			return;
		}		
		
		for (; loc>=0 && loc < MAX_RTPP_COUNT; loc=OSAL_listGetNextPos(pingResults, loc))
		{
			pingElem = (pingNode *)OSAL_listGetNodeByPos(pingResults, loc);
		  	if(!pingElem)
		  	{
				continue;
		  	}
			
			OSAL_hashDoAll(ipHashTable, ping_test, pingElem);			
		}
	}
	else
	{		
		OSAL_trace(ePING, eError, "ping_lauch_action: ping results list is emply.");
		return;
	}
	
	//OSAL_hashDoAll(ipHashTable, ping_test, NULL);
}
