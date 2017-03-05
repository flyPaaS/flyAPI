
#include "OSAL.h"
#include "ping_main.h"
#include "OSAL_cfgfile.h"
#include "OSAL_timer.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>

extern unsigned short cal_chksum(unsigned short *addr, int len);
extern  void tv_sub(struct timeval *out, struct timeval* in);
extern PingGlobalsT PingGlobalData;
//extern ping_probe_result_T *pProbe_results;
extern OSAL_HHASH    ipHashTable;
extern OSAL_HLIST 	 pingResults;

static void ping_show_config()
{

	OSAL_INT32 i;
	OSAL_INT32 loc;
	pingNode *pingElem = OSAL_NULL;
	printf("%-30s: ", "ALL rtpc socket");
	for(i=0; i<PingGlobalData.rtpc_num; i++)
	{
		if(i==0) {
			printf("%s:%s:%d\n", "udp", 
				inet_ntoa(PingGlobalData.report_addr[i].sin_addr), 
				ntohs(PingGlobalData.report_addr[i].sin_port));
		}
		else {
			printf("%-30s: %s:%s:%d\n", "", "udp", 
				inet_ntoa(PingGlobalData.report_addr[i].sin_addr), 
				ntohs(PingGlobalData.report_addr[i].sin_port)); 
		}
	}
	if(i==0)
		printf("\n");
	printf("%-30s: %ds\n", "Ping to other RTPP rate", PingGlobalData.ping_rate);
	printf("%-30s: %d\n", "Rtpc count", PingGlobalData.rtpc_num);
	printf("%-30s: %d\n", "Ping sdk port", PingGlobalData.respond_sdk_port);

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
			printf("%s%-26d: %s\n", "rtpp", loc, pingElem->rtppIp);			
		}
	}

}

void *list_ip(OSAL_HHASH hHash, void  *elem, void *param)
{
	
	ipInfo_t *ip_str = (ipInfo_t*)elem;
	ip_type iptype = (ip_type)param;
	
	if(ip_str != NULL && ip_str->iptype == iptype)
	{
		printf("%-10s: %s\n", (iptype == RTPP_IP) ? "RTPP" : "GATEWAY", ip_str->ip);
	}

	return param;
}

static void ping_list_ips()
{
	OSAL_hashDoAll(ipHashTable, list_ip, RTPP_IP);
	OSAL_hashDoAll(ipHashTable, list_ip, GW_IP);	
}

static void set_ping_rate(OSAL_INT32 ping_rate)
{
	PingGlobalData.ping_rate = ping_rate;
	OSAL_CHAR buff[12] = {0};
	sprintf(buff, "%d", ping_rate);

	refine_cfg_entry(CONFIG_FILE, PING_LABEL_PING_RATE, buff);
}

static void ping_other_rtpp(OSAL_CHAR *rtpp_ip)
{
	if(!rtpp_ip)// dstip[:srcip]
		return;
	
	int i = 0;
	pid_t pid = getppid();
	struct protoent *protocol;
	struct sockaddr_in src_addr, dest_addr, from_addr;
	int ping_sock;
	int nrecved = 0;
	int nsended = 0;
	int lost = 100;

	OSAL_CHAR sendbuffer[PACKET_SIZE];
	OSAL_CHAR recvbuffer[PACKET_SIZE];
	
	OSAL_CHAR sourceip[IP_LEN] = {0};
	OSAL_CHAR destip[IP_LEN] = {0};
 	OSAL_CHAR *pch = strchr(rtpp_ip, ':');
	if(pch){
		strncpy(destip, rtpp_ip, pch-rtpp_ip);
		destip[IP_LEN-1] = '\0';	
		pch++;
		strncpy(sourceip, pch, IP_LEN-1);
	}else{
		strncpy(destip, rtpp_ip, IP_LEN-1);
	}
	
	if( (protocol=getprotobyname("icmp") )==NULL) { 
		OSAL_trace(ePING, eError, "getprotobyname err");
		return;
	}
	if( (ping_sock = socket(AF_INET,SOCK_RAW,protocol->p_proto) )<0)
	{ 
		OSAL_trace(ePING, eError, "socket SOCK_RAW err");
		return ;
	}
	if(strlen(sourceip)){
		memset(&src_addr, 0, sizeof(struct sockaddr_in));
		src_addr.sin_family = AF_INET;
		src_addr.sin_addr.s_addr = inet_addr(sourceip);
		if(bind(ping_sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
			OSAL_trace(ePING, eError, "ping_other_rtpp: bind src addr err.");
			return;
		}
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;	
	dest_addr.sin_addr.s_addr = inet_addr(destip);

	int packsize;
	struct icmp *icmp;
	struct timeval *tval;
	time_t t;

	int n;
	OSAL_INT32  recv_iphdrlen;
	struct ip *recv_ip;
	struct icmp *recv_icmp;

	for(i=0; i<PING_REPEAT; i++)
	{
		//send
		memset(sendbuffer, 0, sizeof(sendbuffer));		
		icmp = (struct icmp*)sendbuffer;
		icmp->icmp_type = ICMP_SHELL_PROBE_T;
		icmp->icmp_code = 0;
		icmp->icmp_seq = (unsigned short)i+1;
		icmp->icmp_id = pid;
		packsize = 8+DATA_LEN;
		tval= (struct timeval *)icmp->icmp_data;	
		gettimeofday(tval, NULL);
		icmp->icmp_cksum = cal_chksum((unsigned short *)icmp, packsize);

		t = time(NULL);
		if(sendto(ping_sock, sendbuffer, packsize, 0, 
			(struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0)
		{
			OSAL_trace(ePING, eWarn, "send %dth prober ICMP to %s err", i+1, rtpp_ip);
			nsended++;
			continue;
		}
		nsended++;

		//receive
		socklen_t fromlen = sizeof(from_addr);	
		memset(recvbuffer, 0, sizeof(recvbuffer));
		n = 0;
		for(;n == 0;)
		{
			if((time(NULL) - t) > 2)
				break;
			n = recvfrom(ping_sock, recvbuffer, PACKET_SIZE, 0,
				(struct sockaddr*)&from_addr, &fromlen);
			if(n < 0) {				
				return;
			}

			recv_ip = (struct ip*)recvbuffer;
			recv_iphdrlen = recv_ip->ip_hl<<2;
			recv_icmp = (struct icmp*)(recvbuffer+recv_iphdrlen);
			if(recv_icmp->icmp_type != ICMP_SHELL_REPLY_T){
				n = 0;
				continue;
			}
			n = n-recv_iphdrlen;
			if(n < 8) {				
				OSAL_trace(ePING, eInfo, "unpaking a illegality ICMP.");
				continue;
			}

			if(recv_icmp->icmp_id==pid && !strncmp(inet_ntoa(from_addr.sin_addr), destip, strlen(destip)))	
			{	
				struct timeval tvrecv;
				struct timeval *tvsend;
				OSAL_UINT32 rtt;
				gettimeofday(&tvrecv, OSAL_NULL);
				tvsend = (struct timeval*)recv_icmp->icmp_data;
				tv_sub(&tvrecv, tvsend);
				rtt=tvrecv.tv_sec*1000+tvrecv.tv_usec/1000;
				printf("%d byte reply from %s: icmp_seq=%u ttl=%d rtt=%dms\n",
					n, inet_ntoa(from_addr.sin_addr), recv_icmp->icmp_seq,
					recv_ip->ip_ttl, rtt);
				nrecved++;
				sleep(1);
				break;
			}
		}		
		sleep(1);
	}
	
	if(nsended > 0 && nsended <= 10){
		lost = (nsended - nrecved)/PING_REPEAT * 100;
		printf("\n--------------------PING statistics-------------------\n");
		printf("%d packets transmitted, %d received , %d%% lost\n" , nsended , nrecved, lost);
	}
		
    close(ping_sock);
}

static int
xsh_show_config (OSAL_SHELL_ARGS)
{
	if(!PingGlobalData.isEnable) {
		printf("\tRtpp colony is closed, please open.\n");
		return OSAL_OK;
	}
		
	BEGIN_OSAL_SHELL_MAP ("show PING module config")
	OSAL_SHELL_NO_ARG ()
	END_OSAL_SHELL_MAP ()

	ping_show_config();	
	return OSAL_OK;
}

static int 
xsh_list_ping_ip(OSAL_SHELL_ARGS)
{
	if(!PingGlobalData.isEnable) {
		printf("\tRtpp colony is closed, please open.\n");
		return OSAL_OK;
	}
	BEGIN_OSAL_SHELL_MAP ("List all ip for ping ")
	OSAL_SHELL_NO_ARG ()
	END_OSAL_SHELL_MAP ()

	if(PingGlobalData.isEnable)
		ping_list_ips();
	return OSAL_OK;
}

static int xsh_set_ping_colony(OSAL_SHELL_ARGS)
{
	OSAL_CHAR tmp[8];
	BEGIN_OSAL_SHELL_MAP ("change ping colony")
	OSAL_SHELL_NO_ARG()
 	END_OSAL_SHELL_MAP ()

	{
		PingGlobalData.isEnable = !PingGlobalData.isEnable;
	}
	sprintf(tmp,"%d",PingGlobalData.isEnable);
	refine_cfg_entry(CONFIG_FILE, PING_LABEL_COLONY, tmp);
	return OSAL_OK;
}

static int xsh_set_ping_rate(OSAL_SHELL_ARGS)
{
	if(!PingGlobalData.isEnable) {
		printf("\tRtpp colony is closed, please open.\n");
		return OSAL_OK;
	}
	OSAL_INT32 ping_rate;
	BEGIN_OSAL_SHELL_MAP ("change ping rate to all rtpp")
	OSAL_SHELL_INT_ARG("pingrate", &ping_rate, NULL, "ping rate to other rtpp")
 	END_OSAL_SHELL_MAP ()


	set_ping_rate(ping_rate);
	return OSAL_OK;
}

static int
xsh_ping_rtpp(OSAL_SHELL_ARGS)
{
	if(!PingGlobalData.isEnable) {
		printf("\tRtpp colony is closed, please open.\n");
		return OSAL_OK;
	}
	OSAL_CHAR rtpp_ip[32] = {0};
	BEGIN_OSAL_SHELL_MAP ("send ping packet to other rtpp")
	OSAL_SHELL_STRING_ARG("rtpp_ip",rtpp_ip, NULL, "ip addr of other rtpp")
 	END_OSAL_SHELL_MAP ()

	ping_other_rtpp(rtpp_ip);
	return OSAL_OK;
	
}

/*======================================
		Extern Function
========================================*/

void ping_init_shell ()
{
	OsalSNode parent;
	parent = osal_register_snode (NULL, "PING", NULL, 0);
	osal_register_snode (parent, "ShowConfig", xsh_show_config, 0);
	osal_register_snode (parent, "ChangeColony", xsh_set_ping_colony, 0);
	osal_register_snode (parent, "SetPingRate", xsh_set_ping_rate, 0);
	osal_register_snode (parent, "ListPingIP", xsh_list_ping_ip, 0);
	osal_register_snode (parent, "PingOtherRtpp", xsh_ping_rtpp, 0);
}         
