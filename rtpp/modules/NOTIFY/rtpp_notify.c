#include <poll.h>
#include "rtpp_notify.h"

static media_notify_t rtpp_media_notify;
static OSAL_TIMER_ID rtpp_addr_syn;
static OSAL_CHAR rtpp_addr[32];
static OSAL_UINT32 tcpMsgSeq = 0;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/
OSAL_INT32 notify_init(void);
OSAL_INT32 notify_main(OSAL_msgHdr *msg_hdr);
OSAL_INT32 notify_end(void);

#ifdef __cplusplus
}
#endif /* __cplusplus*/

void notify_add_conn2head(rtppcon_t *conn)
{
	conn->pre = 0;
	conn->next = rtpp_media_notify.first;
	conn->next->pre = conn;
	rtpp_media_notify.first = conn;
	rtpp_media_notify.num++;
}

void notify_add_conn2tail(rtppcon_t *conn)
{
	rtppcon_t *tmp = rtpp_media_notify.first;

	
	if(tmp){
		while(tmp->next) {
			tmp = tmp->next;
		}
		tmp->next = conn;
	}else{
		rtpp_media_notify.first = conn;
	}
	conn->pre = tmp;
	conn->next = 0;
	rtpp_media_notify.num++;
}

void notify_remove_conn(rtppcon_t *conn)
{
	if(conn->pre) conn->pre->next = conn->next;
	else rtpp_media_notify.first = conn->next;
	if(conn->next) conn->next->pre = conn->pre;
	rtpp_media_notify.num--;
}

rtppcon_t * notify_find_conn(OSAL_INT32 ip)
{
	rtppcon_t *tmp = rtpp_media_notify.first;
	
	while(tmp){
		if(tmp->ip == ip)
			return tmp;
		tmp = tmp->next;
	}
	return 0;
}

rtppcon_t * notify_connect2rtpc(OSAL_INT32 ip,OSAL_INT32 port)
{
	OSAL_INT32 fd;
	OSAL_INT32 res;
	rtppcon_t *conn;
	struct sockaddr_in addr;
	OSAL_INT32 addrlen = sizeof(addr);
	OSAL_INT32 u1 = 1;
	struct pollfd pfd;
	
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip;
	addr.sin_port = htons(port);
	
	fd = socket(AF_INET, SOCK_STREAM,IPPROTO_TCP);
	if (fd == -1){
		OSAL_trace(eNOTIFY, eError,"open socket failed: %s",strerror(errno));
		return NULL;
	}
	
	ioctl(fd, FIONBIO, &u1);
	res = connect(fd,(struct sockaddr *)&addr,addrlen);
	if (res < 0 && errno != EINPROGRESS) {
		OSAL_trace(eNOTIFY, eError,"connect %s[%d] return %s[%d]", inet_ntoa(addr.sin_addr), port,strerror (errno), errno);
		return NULL;
	}
	pfd.fd = fd;
	pfd.events = POLLOUT;
	pfd.revents = 0;
	res = poll(&pfd,1,3000);
	if(res <= 0){
		OSAL_trace(eNOTIFY, eError,"poll failed");
		return NULL;
	}
	
	conn = (rtppcon_t*)osal_allocate(sizeof(rtppcon_t),DEFAULT_FLAGS | MEMF_ZERO_MEMORY, mem_default, MAGIC_NUMBER('r','t','p','p'), NULL);
	conn->ip = ip;
	conn->fd = fd;
	notify_add_conn2tail(conn);
	
	return conn;
}

OSAL_INT32  notify_sendtimeoutt2rtpc(rtppcon_t * conn,OSAL_CHAR *nofify_buf,OSAL_INT32 len)
{
	OSAL_INT32 res,fd;
	Json::Value logMsg;
	OSAL_CHAR buff[4096] = {0};
	std::string data;
	Json::StyledWriter JsonWr;
	OSAL_INT32 total_len = 0;

	logMsg["rtpp"] = Json::Value(rtpp_addr);
	logMsg["notify"] = Json::Value(nofify_buf);	
		
	notify_msg *jsonMsg = (notify_msg *)buff;
	jsonMsg->msg_type = NOTIFY_MEDIA_OUT;
	jsonMsg->body_type = 0;
	jsonMsg->sn = htons((tcpMsgSeq++)%65535);
	
	data = JsonWr.write(logMsg);
	jsonMsg->body_len = htons(data.length() + 16);
	memcpy(jsonMsg->body, data.c_str(), data.length());
	total_len = sizeof(notify_msg) + data.length();

	fd = conn->fd;
	res = send(fd,(OSAL_CHAR *)jsonMsg ,total_len,0);
	if(res <= 0){
		close(fd);
		notify_remove_conn(conn);
		osal_free(conn);
		OSAL_trace(eNOTIFY, eError,"send notify failed");
		return -1;
	}
	return 0;
}

OSAL_INT32 notify_wait_notify_rsp(rtppcon_t * conn)
{
	struct pollfd pfd;
	OSAL_INT32 res,fd;
	OSAL_CHAR  ret;

	fd = conn->fd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	res = poll(&pfd,1,2000);
	if(res > 0){
		res = recv(fd,&ret,1,0);
		if(1 == res && ret == '\0'){
			return 0;
		}
	}
	
	close(fd);
	notify_remove_conn(conn);
	osal_free(conn);
	OSAL_trace(eNOTIFY, eError,"poll failed");
	return -1;
}

OSAL_INT32 notify_media_timeout_once(OSAL_INT32 ip,OSAL_INT32 port,OSAL_CHAR *nofify_buf,OSAL_INT32 len)
{
	rtppcon_t *conn;
	
	conn = notify_find_conn(ip);
	if(!conn){
		OSAL_trace(eNOTIFY, eInfo, "not find notify conn,goto connect %d:%d",ip,port);
		conn = notify_connect2rtpc(ip,port);
		if(!conn) {
			OSAL_trace(eNOTIFY, eInfo, "can not creat notify conn,goto first valid conn");
			conn = rtpp_media_notify.first;
		}
		if(!conn) {
			OSAL_trace(eNOTIFY, eInfo, "first null");
			return -1;
		}
	}
	
	if(notify_sendtimeoutt2rtpc(conn,nofify_buf,len) < 0)
		return -1;
	if(notify_wait_notify_rsp(conn) < 0)
		return -1;
	return 0;
}

OSAL_INT32 media_timeout_notify(OSAL_INT32 ip,OSAL_INT32 port,OSAL_CHAR *notify_buf,OSAL_INT32 len)
{
	OSAL_INT32 i;
	//try 2 times
	//OSAL_trace(eNOTIFY, eWarn, "recv media timeout msg:%s to %d:%d",notify_buf,ip,port);
	for(i = 0; i < 2; i++){
		if(0 == notify_media_timeout_once(ip,port,notify_buf,len)) break;
	}
	return 0;
}

OSAL_INT32 notify_tcp_conn(OSAL_msgHdr *pMsg)
{
	rtppcon_t *conn;
	
	conn = (rtppcon_t*)osal_allocate(sizeof(rtppcon_t),DEFAULT_FLAGS | MEMF_ZERO_MEMORY, mem_default, MAGIC_NUMBER('r','t','p','p'), NULL);
	if(!conn){
		OSAL_trace(eNOTIFY, eError,"alloc conn failed");
		return -1;
	}
	conn->next = rtpp_media_notify.first;
	rtpp_media_notify.first = conn;
	rtpp_media_notify.num++;
	
	return 0;
}

void start_syn_rtpp_addr()
{
	OSAL_timerMsgHdrT timerMsg;

	timerMsg.moduleId = eNOTIFY;
	timerMsg.timerMsgType = eOsalSysMsgIdTimer;
	timerMsg.param1 = 0;
	rtpp_addr_syn = OSAL_stimerStart(&timerMsg, 10);
}

void notify_syn_timer_out()
{
	OSAL_msgHdr msg = {0};
	msg.msgId = RTPP_AGENT_ADDR_SYN;
	OSAL_sendMsg(eRA,&msg);
}

void notify_syn_rtpp_addr(OSAL_msgHdr *pMsg)
{
	if(pMsg->contentLen > 32 || pMsg->contentLen < 7 || !pMsg->pContent)
		return;

	strcpy(rtpp_addr,(OSAL_CHAR *)pMsg->pContent);
}

OSAL_INT32 notify_report_log(OSAL_INT32 ip,OSAL_INT32 port,OSAL_CHAR *notify_buf,OSAL_INT32 len)
{
	rtppcon_t *conn;	
	OSAL_INT32 res;
	Json::Value logMsg;
	OSAL_CHAR buff[4096] = {0};
	std::string data;
	Json::StyledWriter JsonWr;
	OSAL_INT32 total_len = 0;
	
	conn = notify_find_conn(ip);
	if(!conn){
		OSAL_trace(eNOTIFY, eInfo, "not find notify conn,goto connect %d:%d",ip,port);
		conn = notify_connect2rtpc(ip,port);
		if(!conn) {
			OSAL_trace(eNOTIFY, eInfo, "can not creat notify conn,goto first valid conn");
			conn = rtpp_media_notify.first;
		}
		if(!conn) {
			OSAL_trace(eNOTIFY, eInfo, "first null");
			return -1;
		}
	}

	logMsg["rtpp"] = Json::Value(rtpp_addr);
	logMsg["log"] = Json::Value(notify_buf);

	notify_msg *jsonMsg = (notify_msg *)buff;
	jsonMsg->msg_type = NOTIFY_LOG;
	jsonMsg->body_type = 0;
	jsonMsg->sn = htons((tcpMsgSeq++)%65535);
	
	data = JsonWr.write(logMsg);
	jsonMsg->body_len = htons(data.length()+ 16);
	memcpy(jsonMsg->body, data.c_str(), data.length());
	total_len = sizeof(notify_msg) + data.length();
	
	res = send(conn->fd,(OSAL_CHAR *)jsonMsg ,total_len,0);
	if(res <= 0){
		close(conn->fd);
		notify_remove_conn(conn);
		osal_free(conn);
		OSAL_trace(eNOTIFY, eError,"send notify failed");
		return -1;
	}
	return 0;
}

OSAL_INT32 notify_report_bill(OSAL_INT32 ip,OSAL_INT32 port,OSAL_CHAR *notify_buf,OSAL_INT32 len)
{
	rtppcon_t *conn;	
	OSAL_INT32 res;
	Json::Value billMsg;
	OSAL_CHAR buff[1024] = {0};
	OSAL_CHAR md5buff[128];
	std::string data;
	Json::StyledWriter JsonWr;
	OSAL_INT32 total_len = 0;
	int i;
	
	conn = notify_find_conn(ip);
	if(!conn){
		OSAL_trace(eNOTIFY, eInfo, "not find notify conn,goto connect %d:%d",ip,port);
		conn = notify_connect2rtpc(ip,port);
		if(!conn) {
			OSAL_trace(eNOTIFY, eInfo, "can not creat notify conn,goto first valid conn");
			conn = rtpp_media_notify.first;
		}
		if(!conn) {
			OSAL_trace(eNOTIFY, eInfo, "first null");
			return -1;
		}
	}

	billMsg["rtpp"] = Json::Value(rtpp_addr);
	billMsg["bill"] = Json::Value(notify_buf);

	notify_msg *jsonMsg = (notify_msg *)buff;
	jsonMsg->msg_type = NOTIFY_BILL;
	jsonMsg->body_type = 0;
	jsonMsg->sn = htons((tcpMsgSeq++)%65535);

	sprintf(md5buff,"%s:%s:%d",notify_buf,MD5SECR,ntohs(jsonMsg->sn));
	//OSAL_trace(eNOTIFY, eSys, "md5buff:%s",md5buff);
	MD5_str((const unsigned char *)md5buff,strlen(md5buff),jsonMsg->md5);
	/*
	for(i = 0;i<16;i++)
		printf("[%02x] ",jsonMsg->md5[i]);
	*/
	data = JsonWr.write(billMsg);
	jsonMsg->body_len = htons(data.length() + 16);
	memcpy(jsonMsg->body, data.c_str(), data.length());
	OSAL_trace(eNOTIFY, eDebug, "jsonMsg->body:%s",jsonMsg->body);
	total_len = sizeof(notify_msg) + data.length();
	
	res = send(conn->fd,(OSAL_CHAR *)jsonMsg ,total_len,0);
	if(res <= 0){
		close(conn->fd);
		notify_remove_conn(conn);
		osal_free(conn);
		OSAL_trace(eNOTIFY, eError,"send notify failed");
		return -1;
	}
	return 0;
}


OSAL_INT32 notify_init (void)
{
	start_syn_rtpp_addr();
	return OSAL_OK;
}

OSAL_INT32 notify_main (OSAL_msgHdr *pMsg)
{
	switch (pMsg->msgId){
		case MEDIA_TIMEOUT_NOFIFY:
			media_timeout_notify(pMsg->param,pMsg->param2,(OSAL_CHAR *)pMsg->pContent,pMsg->contentLen);
		 	break;
		case RTPP_REPORT_LOG:
			notify_report_log(pMsg->param,pMsg->param2,(OSAL_CHAR *)pMsg->pContent,pMsg->contentLen);
			break;
		case RTPP_REPORT_BILL:
			notify_report_bill(pMsg->param,pMsg->param2,(OSAL_CHAR *)pMsg->pContent,pMsg->contentLen);
			break;
	  	case eOsalSysMsgIdTimer:
	  		notify_syn_timer_out();
		 	break;
		case RTPP_AGENT_ADDR_SYN:
			notify_syn_rtpp_addr(pMsg);
			break;
	  	default:
		  	OSAL_trace(eNOTIFY, eWarn, "invalid msg type[%d].",pMsg->msgId);
		  break;
	}

	return OSAL_OK;	
}

OSAL_INT32 notify_end (void)
{
	return OSAL_OK;
}
