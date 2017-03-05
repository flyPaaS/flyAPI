#include "rtpp_util.h"
#include "rtpp_main.h"


/*把-1改成0兼容端口表未初始化的情况*/
#define RTPP_PORT_NULL 0

table_info_t table[RTPP_MAX_LOCAL_NUM];

OSAL_INT32 init_controlfd()
{
	OSAL_INT32 fd;
	OSAL_CHAR *tmp;
	OSAL_CHAR ip[RTPP_MAX_IP_LEN] = {0};
	OSAL_INT32 port;
	//default main ip is the first
	if('\0' != RtppGlobals.command_socket[0]&& NULL != (tmp = strchr(RtppGlobals.command_socket,':'))&&isdigit(*(tmp+1))){
		*tmp = 0;
		strncpy(ip,RtppGlobals.command_socket,RTPP_MAX_IP_LEN-1);
		port = atoi(tmp+1);
		*tmp = ':';
	}else{
		OSAL_trace(eRTPP, eError,"command socket %s err",RtppGlobals.command_socket);
		return -1;
	}
	
	OSAL_trace(eRTPP, eSys,"command socket ip %s,port %d",ip,port);
		
	if((fd = rtpp_create_sock(ip,port,0,SOCK_DGRAM,IPPROTO_UDP)) < 0){
		return -1;
	}
	OSAL_async_select(eRTPP,fd,RTPP_UDP_COMMAND,NULL,NULL);
	RtppGlobals.controlfd = fd;
	return 0;
}

OSAL_INT32 init_port_table()
{
    OSAL_INT32 i,j,port, fd;
	OSAL_INT32 tos = TOS;
	alloc_info_t *p;

	for(i = 0; i < RtppGlobals.localipnum; i++){
		p = (alloc_info_t*)osal_allocate(sizeof(alloc_info_t)*RTPP_ALLOC_PORT_NUM,DEFAULT_FLAGS | MEMF_ZERO_MEMORY, mem_default, MAGIC_NUMBER('C','T','G','W'), NULL);
		if(!p){
			OSAL_trace(eRTPP, eError,"alloc alloc_info_t  failed");
			return -1;
		}
		table[i].p = p;
		j = 0;
		port = 35000;
		
		pthread_mutex_init(&table[i].lock, NULL);

		for(; port < 60001; port += 2){
			fd = rtpp_create_sock(RtppGlobals.localip[i],port,tos,SOCK_DGRAM,IPPROTO_UDP);
			if(fd > 0){
				table[i].p[j].fd = fd;
				table[i].p[j].port = port;
				table[i].p[j].index = i;
				fd = rtpp_create_sock(RtppGlobals.localip[i],port+1,tos,SOCK_DGRAM,IPPROTO_UDP);
				if(fd>0){
					table[i].p[j].rtcpfd = fd;
					table[i].p[j].next = &table[i].p[j+1];
					j++;
					if(j == RTPP_ALLOC_PORT_NUM) break;
				}else{
					close(table[i].p[j].fd);
				}
			}else continue;
		}
		if(60000 == port){
			OSAL_trace(eRTPP, eError,"alloc port on ip: %s failed.", RtppGlobals.localip[i]);
			return -1;
		}
		OSAL_trace(eRTPP, eSys,"alloc port %d on ip: %s succ.", RTPP_ALLOC_PORT_NUM*2,RtppGlobals.localip[i]);
		table[i].p[j-1].next = RTPP_PORT_NULL;
		table[i].free = table[i].p;
		table[i].free_tail = &table[i].p[j-1];
	}
	return 0;
}

alloc_info_t *rtpp_alloc_port(OSAL_INT32 index)
{
	alloc_info_t *t;
/*
	if(index < RTPP_ALLOC_PORT_NUM ){
		return 0;
	}
*/
	if(index < 0 || index >= RtppGlobals.localipnum)
		return NULL;
	
	pthread_mutex_lock(&table[index].lock);
	t = table[index].free;
	if(RTPP_PORT_NULL == t){
		pthread_mutex_unlock(&table[index].lock);
		return NULL;
	}
	table[index].free = t->next;
	if(RTPP_PORT_NULL == table[index].free) 
		table[index].free_tail = RTPP_PORT_NULL;
	table[index].used++;
	pthread_mutex_unlock(&table[index].lock);
	return t;
}

OSAL_INT32 rtpp_free_port(alloc_info_t *pinfo)
{
	OSAL_INT32 index = pinfo->index;
	pinfo->next = RTPP_PORT_NULL;
	pthread_mutex_lock(&table[index].lock);
	if(RTPP_PORT_NULL == table[index].free_tail){
		table[index].free = pinfo;
	}else{
		table[index].free_tail->next = pinfo;
	}
    table[index].free_tail= pinfo;
	table[index].used--;
	pthread_mutex_unlock(&table[index].lock);
	return 0;
}

OSAL_INT32 rtpp_selct_alloc_port(OSAL_INT32 mod_id,OSAL_CHAR index,OSAL_INT32 mix,port_info_t *port_info)
{
	alloc_info_t *alloc;
	
	alloc = rtpp_alloc_port(index);
	if(NULL == alloc){
		OSAL_trace(eRTPP, eError,"IP %d is alloc failed", index);
		return -1;
	}
	alloc->next = 0;
	if(mix)
	{
		if (OSAL_OK != OSAL_async_select (mod_id, alloc->fd, RTPP_UDP_MIX_RTP, OSAL_NULL, port_info)){
			OSAL_trace (eRTPP, eError, "select mix rtp failed.");
			rtpp_free_port(alloc);
			return -1;
		}
		
		if (OSAL_OK != OSAL_async_select (mod_id, alloc->rtcpfd, RTPP_UDP_MIX_RTP, OSAL_NULL, port_info)){
			OSAL_trace (eRTPP, eError, "select mix rtcp failed.");
			OSAL_async_select (mod_id, alloc->fd, 0, OSAL_NULL, 0);
			rtpp_free_port(alloc);
			return -1;
		}	
	}
	else
	{
		if (OSAL_OK != OSAL_async_select (mod_id, alloc->fd, RTPP_UDP_RTP, OSAL_NULL, port_info)){
			OSAL_trace (eRTPP, eError, "select rtp failed.");
			rtpp_free_port(alloc);
			return -1;
		}
		
		if (OSAL_OK != OSAL_async_select (mod_id, alloc->rtcpfd, RTPP_UDP_RTP, OSAL_NULL, port_info)){
			OSAL_trace (eRTPP, eError, "select rtcp failed.");
			OSAL_async_select (mod_id, alloc->fd, 0, OSAL_NULL, 0);
			rtpp_free_port(alloc);
			return -1;
		}
	}
	port_info->p = alloc;

	/*分配端口后清空缓存*/
	for(;;){
		struct sockaddr_in from_addr;
		int n;
		socklen_t fromlen = sizeof(from_addr);
		char tmpbuf[1] = {0};
		
		n = recvfrom(alloc->fd, tmpbuf, 1, 0,
			(struct sockaddr*)&from_addr, &fromlen);
		if(n < 0){
			break;
		}
	}

	/*分配端口后清空缓存*/
	for(;;){
		struct sockaddr_in from_addr;
		int n;
		socklen_t fromlen = sizeof(from_addr);
		char tmpbuf[1] = {0};
		
		n = recvfrom(alloc->rtcpfd, tmpbuf, 1, 0,
			(struct sockaddr*)&from_addr, &fromlen);
		if(n < 0){
			break;
		}
	}
			
	return 0;
}

OSAL_INT32 rtpp_disselct_free_port(OSAL_INT32 mod_id,alloc_info_t *dealloc)
{

	if (OSAL_OK != OSAL_async_select (mod_id, dealloc->fd, 0, OSAL_NULL, 0)){
		OSAL_trace (eRTPP, eError, "remove %d poll rtp failed.", dealloc->fd);
		return -1;
	}
	
	if (OSAL_OK != OSAL_async_select (mod_id, dealloc->rtcpfd, 0, OSAL_NULL, 0)){
		OSAL_trace (eRTPP, eError, "remove %d poll rtcp failed.", dealloc->rtcpfd);
		return -1;
	}

	/*释放端口后清空缓存*/
	for(;;){
		struct sockaddr_in from_addr;
		int n;
		socklen_t fromlen = sizeof(from_addr);
		char tmpbuf[1] = {0};
		
		n = recvfrom(dealloc->fd, tmpbuf, 1, 0,
			(struct sockaddr*)&from_addr, &fromlen);
		if(n < 0){
			break;
		}
	}

	/*释放端口后清空缓存*/
	for(;;){
		struct sockaddr_in from_addr;
		int n;
		socklen_t fromlen = sizeof(from_addr);
		char tmpbuf[1] = {0};
		
		n = recvfrom(dealloc->rtcpfd, tmpbuf, 1, 0,
			(struct sockaddr*)&from_addr, &fromlen);
		if(n < 0){
			break;
		}
	}
	
	rtpp_free_port(dealloc);
			
	return 0;
}

OSAL_INT32 rtpp_selct_port(OSAL_INT32 mod_id,OSAL_INT32 mix,port_info_t *port_info)
{
	if(mix)
	{
		if (OSAL_OK != OSAL_async_select (mod_id, port_info->p->fd, RTPP_UDP_MIX_RTP, OSAL_NULL, port_info)){
			OSAL_trace (eRTPP, eError, "select mix rtp failed.");
			rtpp_free_port(port_info->p);
			return -1;
		}
		
		if (OSAL_OK != OSAL_async_select (mod_id, port_info->p->rtcpfd, RTPP_UDP_MIX_RTP, OSAL_NULL, port_info)){
			OSAL_trace (eRTPP, eError, "select mix rtcp failed.");
			OSAL_async_select (mod_id, port_info->p->fd, 0, OSAL_NULL, 0);
			rtpp_free_port(port_info->p);
			return -1;
		}	
	}
	else
	{
		if (OSAL_OK != OSAL_async_select (mod_id, port_info->p->fd, RTPP_UDP_RTP, OSAL_NULL, port_info)){
			OSAL_trace (eRTPP, eError, "select rtp failed.");
			rtpp_free_port(port_info->p);
			return -1;
		}
		
		if (OSAL_OK != OSAL_async_select (mod_id, port_info->p->rtcpfd, RTPP_UDP_RTP, OSAL_NULL, port_info)){
			OSAL_trace (eRTPP, eError, "select rtcp failed.");
			OSAL_async_select (mod_id, port_info->p->fd, 0, OSAL_NULL, 0);
			rtpp_free_port(port_info->p);
			return -1;
		}
	}
			
	return 0;
}



OSAL_INT32 rtpp_disselct_port(OSAL_INT32 mod_id,alloc_info_t *dealloc)
{

	if (OSAL_OK != OSAL_async_select (mod_id, dealloc->fd, 0, OSAL_NULL, 0)){
		OSAL_trace (eRTPP, eError, "remove poll rtp failed.");
		return -1;
	}
	
	if (OSAL_OK != OSAL_async_select (mod_id, dealloc->rtcpfd, 0, OSAL_NULL, 0)){
		OSAL_trace (eRTPP, eError, "remove poll rtcp failed.");
		return -1;
	}
				
	return 0;
}

static void rtpp_update_portinfo(port_info_t *portinfo, OSAL_INT32 ip, OSAL_INT32 port, OSAL_INT32 asy)
{
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = ip;
	OSAL_trace (eRTPP, eInfo, "update port info ip %s port %d asy %d",inet_ntoa(addr.sin_addr),port,asy);
	portinfo->fip = ip;
	portinfo->fport = htons(port);
	portinfo->frtcpport = htons(port+1);
	portinfo->asym = asy;	
}

void rtpp_update_left_aport(OSAL_INT32 ip,OSAL_INT32 port_index, OSAL_INT32 aport,OSAL_INT32 asy,rtpp_session_t* ss)
{
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = ip;
	OSAL_trace (eRTPP, eInfo, "update left audio ip %s port %d asy %d",inet_ntoa(addr.sin_addr),aport,asy);
	rtpp_update_portinfo(&ss->left.audio[port_index], ip, aport, asy);
}
void rtpp_update_right_aport(OSAL_INT32 ip,OSAL_INT32 port_index, OSAL_INT32 aport,OSAL_INT32 asy,rtpp_session_t* ss)
{
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = ip;
	OSAL_trace (eRTPP, eInfo, "update right audio ip %s port %d asy %d",inet_ntoa(addr.sin_addr),aport,asy);
	rtpp_update_portinfo(&ss->right.audio[port_index], ip, aport, asy);
}
void rtpp_update_left_vport(OSAL_INT32 ip,OSAL_INT32 port_index, OSAL_INT32 vport,OSAL_INT32 asy,rtpp_session_t* ss)
{
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = ip;
	OSAL_trace (eRTPP, eInfo, "update left video ip %s port %d asy %d",inet_ntoa(addr.sin_addr),vport,asy);
	rtpp_update_portinfo(&ss->left.video[port_index], ip, vport, asy);
}
void rtpp_update_right_vport(OSAL_INT32 ip,OSAL_INT32 port_index, OSAL_INT32 vport,OSAL_INT32 asy,rtpp_session_t* ss)
{
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = ip;
	OSAL_trace (eRTPP, eInfo, "update right video ip %s port %d asy %d",inet_ntoa(addr.sin_addr),vport,asy);
	rtpp_update_portinfo(&ss->right.video[port_index], ip, vport, asy);
}

OSAL_INT32 rtpp_pop_port(OSAL_INT32 branche,OSAL_INT32 port_index, OSAL_INT32 mod_id,OSAL_CHAR index,OSAL_INT32 ip,OSAL_INT32 aport,
		OSAL_INT32 vport,OSAL_INT32 video,OSAL_INT32 asy,OSAL_INT32 mix, OSAL_INT32 fec_mode, rtpp_session_t* ss)
{
	if(index < 0){
		OSAL_trace (eRTPP, eError, "pop port index err",index);
		return -1;
	}
	
	switch(branche){
		case RTPP_BRANCHE_LEFT:
			rtpp_update_right_aport(ip,port_index, aport,asy,ss);
			if(rtpp_selct_alloc_port(mod_id,index,mix,&ss->left.audio[port_index])<0){
				OSAL_trace (eRTPP, eError, "fail to select port");
				return -1;
			}
			ss->left.audio[port_index].va_flag = RTPP_LEFT_AUDIO;
			ss->left.audio[port_index].ss = ss;
			ss->left.audio[port_index].fec_mode = fec_mode;
			if(video){
				rtpp_update_right_vport(ip,port_index, vport,asy,ss);
				if(rtpp_selct_alloc_port(mod_id,index,mix,&ss->left.video[port_index])<0){
					OSAL_trace (eRTPP, eError, "fail to select port");
					return -1;
				}
				ss->left.video[port_index].va_flag = RTPP_LEFT_VIDEO;					
				ss->left.video[port_index].ss = ss;
			}
			break;
		case RTPP_BRANCHE_RIGHT:
			rtpp_update_left_aport(ip,port_index, aport,asy,ss);
			if(rtpp_selct_alloc_port(mod_id,index,mix,&ss->right.audio[port_index]) < 0){
				OSAL_trace (eRTPP, eError, "fail to select port");
				return -1;
			}
			ss->right.audio[port_index].va_flag = RTPP_RIGHT_AUDIO;		
			ss->right.audio[port_index].ss = ss;
			ss->right.audio[port_index].fec_mode = fec_mode;
          
			if(video){
				rtpp_update_left_vport(ip,port_index, vport,asy,ss);
				if(rtpp_selct_alloc_port(mod_id,index,mix,&ss->right.video[port_index])<0){					
					OSAL_trace (eRTPP, eError, "fail to select port");
					return -1;
				}
				ss->right.video[port_index].va_flag = RTPP_RIGHT_VIDEO;
				ss->right.video[port_index].ss = ss;
			}
			break;
		default:
			OSAL_trace (eRTPP, eError, "remove poll rtp2 failed.");
			return -1;
	}
	return 0;
}

OSAL_INT32 command_parse(OSAL_CHAR *buf,OSAL_INT32 len,OSAL_CHAR *argv[],OSAL_INT32 *argc)
{
	OSAL_INT32 i;
	OSAL_INT32 para_num = 1;

	argv[0] = buf;
	
	for(i = 0; i < len; i++){
		if(' ' == buf[i] || '\n' == buf[i] || '\r' == buf[i]){
			argv[para_num++] = buf + i + 1;
			buf[i] = 0;
		}
	}
	*argc = para_num;
	return 0;
}


OSAL_INT32 check_ip_list(OSAL_CHAR *list,OSAL_CHAR deli)
{
	OSAL_CHAR *tmp,*pos;
	OSAL_INT32 ip;

	pos = list;
	
	while('\0' != *pos){
		if(NULL != (tmp = strchr(pos,deli))){
			*tmp=0;
			if(1 != inet_pton(AF_INET,pos,&ip)){
				OSAL_trace(eRTPP, eError, "ip:%s error in list %s",tmp,list);
				return -1;
			}
			*tmp='/';
			pos = tmp + 1;
		}else{
			if(1 != inet_pton(AF_INET,pos,&ip)){
				OSAL_trace(eRTPP, eError, "ip:%s error in list %s",tmp,list);
				return -1;
			}else break;
		}
	}
	return 0;
}

OSAL_INT32 rtpp_ip_check(OSAL_INT32 ip)
{	
	OSAL_INT32 i;
	for(i = 0; i < RtppGlobals.rtpcnum; i++){
		if(ip == RtppGlobals.rtpc[i]){
			break;
		}
	}
	if(i ==  RtppGlobals.rtpcnum){
		return -1;
	}
	return 0;
}

OSAL_INT32 get_callid (OSAL_CHAR *buf,OSAL_CHAR *callid)
{
	OSAL_CHAR *dot;
	
	dot = strrchr(buf,'.');
	if(NULL == dot){
		return -1;
	}
	*dot = 0;
	snprintf(callid,64,"%s",buf+1);
	*dot = '.';
	return OSAL_OK;
}

OSAL_INT32 rtpp_reply_err (OSAL_CHAR *cookie,OSAL_INT32 errcode,OSAL_INT32 ipvalue,OSAL_UINT16 port)
{
	OSAL_CHAR buf[1024];
	OSAL_INT32 len;
	
	len = snprintf(buf,1024,"%s E%d",cookie,errcode);
	
	rtpp_udp_trans(RtppGlobals.controlfd,buf,len, ipvalue, port);

	return 0;
}

OSAL_INT32 rtpp_reply_port (OSAL_CHAR *cookie, OSAL_INT8 branche,  OSAL_INT32 port_index, OSAL_UINT16 aport,OSAL_UINT16 vport,OSAL_INT32 ipvalue,OSAL_UINT16 port)
{
	OSAL_CHAR buf[1024];
	OSAL_INT32 len;

	if(!vport){

		len = snprintf(buf,1024,"%s %d %d %d",cookie,aport, branche, port_index);

	}else{
		len = snprintf(buf,1024,"%s %d/%d %d %d",cookie,aport,vport, branche, port_index);
	}
	
	rtpp_udp_trans(RtppGlobals.controlfd,buf,len, ipvalue, port);

	return 0;
}

OSAL_INT32 rtpp_reply_ok (OSAL_CHAR *cookie,OSAL_INT32 ipvalue,OSAL_UINT16 port)
{
	OSAL_CHAR buf[1024];
	OSAL_INT32 len;
	
	len = snprintf(buf,1024,"%s 0",cookie);
	
	rtpp_udp_trans(RtppGlobals.controlfd,buf,len, ipvalue, port);

	return 0;
}


OSAL_INT32 rtpp_d_reply_ok (OSAL_CHAR *cookie, OSAL_INT32 branche,OSAL_INT32 port_index, OSAL_INT32 ipvalue, OSAL_UINT16 port)


{
	OSAL_CHAR buf[1024];
	OSAL_INT32 len;
	len = snprintf(buf,1024,"%s %d:%d",cookie, branche, port_index);	

	OSAL_trace (eRTPP, eDebug, "d reply ok is %s", buf);
	rtpp_udp_trans(RtppGlobals.controlfd,buf,len, ipvalue, port);

	return 0;
}
OSAL_INT32 rtpp_d_reply_s_ok (OSAL_CHAR *cookie,OSAL_INT32 branche, OSAL_INT32 port_index, OSAL_INT32 ipvalue,
	OSAL_UINT16 port, double left_loss, double right_loss, OSAL_INT32 left_pt, OSAL_INT32 right_pt,OSAL_CHAR *left_mgw, 
	OSAL_CHAR *right_mgw,OSAL_UINT32 lrr, OSAL_UINT32 rrr, OSAL_UINT32 lrs, OSAL_UINT32 rrs, OSAL_CHAR *transmsg,
	OSAL_UINT32 rx_bytes,OSAL_UINT32 tx_bytes)
{
	OSAL_CHAR buf[1024];
	OSAL_INT32 len;
	
	len = snprintf(buf,1024,"%s %d:%d %0.3f %0.3f %d %d %s %s %u %u %u %u %s %u %u",
		cookie, branche, port_index, left_loss, right_loss, 
		left_pt, right_pt, left_mgw, right_mgw,lrr, rrr, lrs, rrs, transmsg,
		rx_bytes,tx_bytes);	
	OSAL_trace (eRTPP, eDebug, "d reply ok is %s", buf);
	rtpp_udp_trans(RtppGlobals.controlfd,buf,len, ipvalue, port);

	return 0;
}


OSAL_CHAR *get_link_addr(OSAL_CHAR *s,OSAL_CHAR *l)
{
	OSAL_INT32 i;
	for(i = 0; i < RTPP_MAX_IP_LEN - 1;i++){
		if((!isdigit(s[i]))&& '.' != s[i]){
			break;
		}
		l[i] = s[i];
	}
	if(i > 6 && i < RTPP_MAX_IP_LEN){
		l[i] = 0;
		return s+i-1;
	}
	return NULL;
}


OSAL_INT32 check_link_addr(OSAL_CHAR *link_ip)
{
	OSAL_INT32 i = 0;
	
	for(i = 0; i < RtppGlobals.localipnum; i++){
		if(!strcmp(RtppGlobals.localip[i],link_ip)){
			break;
		}
		if(!strcmp(RtppGlobals.localip[i], "0.0.0.0")) {
			break;
		}
	}
	if(i == RtppGlobals.localipnum){
		return -1;
	}
	return i;
}


OSAL_INT32 get_record_callid(const OSAL_CHAR *str, OSAL_CHAR **record_callid, OSAL_CHAR **end)
{
    const char *t;

    if (*str == '[') 
	{
		str++;
		for (t = str; *str != '\0'; str++) 
		{		
			if (*str == ']')
				break;
		}
		if (*str != ']')
		    return (-1);
	}
	else
		return -1;
	
	if (t == str)
		return (-1);
	
	*end = (char *)(str + 1);
    *record_callid = (char *)t;
	
    return(str - t);
}

OSAL_INT32 get_calleeMideaInfo(OSAL_CHAR *msg, int msg_len,OSAL_CHAR *calleeMediaIp,OSAL_CHAR *calleeMediaPort,OSAL_CHAR *calleeMediaVPort)
{
    char *t = NULL;
	char *first_semicolon = NULL;
	char *secord_semicolon = NULL;

	for(t = msg; *t != 0; t++)
	{
		if(*t == ';')
		{
			if(first_semicolon == NULL)
				first_semicolon = t;
			else
				secord_semicolon = t;
		}
	}

	if(first_semicolon == NULL || secord_semicolon == NULL)
		return -1;
		
	strncpy(calleeMediaIp,msg,first_semicolon - msg);
	strncpy(calleeMediaPort,first_semicolon + 1,secord_semicolon - (first_semicolon+1));
	strcpy(calleeMediaVPort,secord_semicolon + 1);

	
	return 0;
}


