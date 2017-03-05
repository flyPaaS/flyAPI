#include "ra.h"
#include "ra_config.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/
OSAL_INT32 ra_init(void);
OSAL_INT32 ra_main(OSAL_msgHdr *msg_hdr);
void ra_end(void);

#ifdef __cplusplus
}
#endif /* __cplusplus*/

tcp_conn_t  *raTcpConn = NULL;
static OSAL_UINT32 tcpMsgSeq = 0;
flowStat rtppFlowStat[2] = {0};

OSAL_INT32 test_mode = 0;
OSAL_INT8  disc_rtpp[16] = {0};

extern OSAL_INT32 init_ra_nbr();
extern OSAL_INT32 init_rts();
extern void nbrCalcTimeoutHd();
extern void nbrTxPingTimeoutHd();
extern void nbrProcMsgNbList(OSAL_CHAR *msg_body,OSAL_UINT32 body_len);
extern void nbrRxPingMsg(OSAL_INT32 sock);
extern void nbrResetTxPingTimer();
extern void nbrResetCalcPingTimer();
extern void nbrShowPingConf();
extern void nbrCreateBakSocket();
extern void nbrStartTxPingTimer();
extern void nbrStartCalcPingTimer();
extern void nbrStopTxPingTimer();
extern void nbrStopCalcPingTimer();
extern void ra_init_shell ();
extern void rt_switch();

static void start_connect_timer()
{
	tcp_conn_t *conn = raTcpConn;
	OSAL_timerMsgHdrT timerMsg;

	timerMsg.moduleId = eRA;
	timerMsg.timerMsgType = eOsalSysMsgIdTimer;
	timerMsg.param1 = TIMER_TCP_CONNECT;
	conn->tcp_timer = OSAL_stimerStart(&timerMsg, 3 * 1000);
}

static void init_tcp_connect()
{
	Correlator corr = MAGIC_NUMBER('R','A','T','C');	
	if(NULL == raTcpConn){
		raTcpConn = (tcp_conn_t *)osal_quick_allocate(sizeof(tcp_conn_t),DEFAULT_FLAGS,corr,NULL);
		if(NULL == raTcpConn)
			exit(-1);
		raTcpConn->sock = -1;
		raTcpConn->status = RA_INVALID;
		raTcpConn->hb_loss_cnt = 0;
		raTcpConn->conn_times = 0;
		raTcpConn->bakFlag = 0;
		raTcpConn->bakStatus = 0;
	}
}
static OSAL_INT32 create_tcp_sock()
{
	OSAL_INT32 on = 1; /* on. */
	tcp_conn_t *conn = raTcpConn ;		
	
	if(conn->sock > 0){
		return OSAL_ERROR;
	}	
	if((conn->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		OSAL_trace (eRA, eError, "create tcp socket error :%d.",errno);
		return OSAL_ERROR;
	}
	//setsockopt (conn->sock, SOL_SOCKET, SO_REUSEPORT,(void *) &state, sizeof (int));
	setsockopt (conn->sock, SOL_SOCKET, SO_KEEPALIVE,(void *) &on, sizeof (int));

	conn->status = RA_SOCK_INITED;
	
	return OSAL_OK;
	
}

static void close_tcp_sock()
{
	if(raTcpConn->status == RA_REGISTED){
		nbrStopTxPingTimer();
		nbrStopCalcPingTimer();
	}
	OSAL_async_select(eRA, raTcpConn->sock, NULL, NULL, NULL);
	close(raTcpConn->sock);
	raTcpConn->sock = -1;
	raTcpConn->status = RA_INVALID;
	raTcpConn->hb_loss_cnt = 0;
	raTcpConn->rcv_len = 0;
	raTcpConn->conn_times = 0;
	rt_switch();
}

static OSAL_INT32 connect_to_router()
{
	struct sockaddr_in router_addr;
	tcp_conn_t *conn = raTcpConn ;		
	OSAL_INT32 ret;

	if(conn->sock < 0){
		ret = create_tcp_sock();
		if(ret != OSAL_OK)
			return OSAL_ERROR;
	}

	if(conn->status == RA_SOCK_CONNED)
		return OSAL_OK;

	bzero(&router_addr, sizeof(router_addr));
	router_addr.sin_family = AF_INET;
	router_addr.sin_port = htons(conn->router_port);

	if(inet_pton(AF_INET, conn->router_ip_str, &router_addr.sin_addr) < 0){
		OSAL_trace (eRA, eError, "sa_tcp_connect inet_pton fail,error:%d",errno);
		return OSAL_ERROR;
	}
	ret = connect(conn->sock, (struct sockaddr*)&router_addr, sizeof(router_addr));
	if (ret < 0){
		OSAL_trace(eRA, eWarn, "connect peer failed!",conn->sock);
		OSAL_trace (eRA, eDebug,"sock : %d,connet ret < 0\n",conn->sock);
		return OSAL_ERROR;
	}

	if (OSAL_OK != OSAL_async_select(eRA, conn->sock, RA_MAIN_MSG, OSAL_NULL, OSAL_NULL)) {
	        OSAL_trace(eRA, eError, "select sa socket %d failed.", conn->sock);
	        close( conn->sock);
	        conn->sock = -1;
			conn->status = RA_INVALID;
	        return OSAL_ERROR;
	}
	
	conn->status = RA_SOCK_CONNED;

	OSAL_trace(eRA, eDebug, "connect router %s success!", conn->router_ip_str);
	
	
	return OSAL_OK;
}
void ra_show_conf()
{
	printf("router_addr     :    %s\n",raTcpConn->router_ip_str);
	printf("router_port     :    %d\n",raTcpConn->router_port);
	printf("agent_addr      :    %s\n",raTcpConn->self_ip_str);
	printf("agent_addr_bak  :    %s\n",raTcpConn->bak_ip_str);
	nbrShowPingConf();
}

OSAL_INT32 tx_tcp_msg_json(OSAL_UCHAR type,Json::Value &value)
{
	tcp_conn_t *conn = raTcpConn;
	OSAL_CHAR buff[4096] = {0};
	OSAL_INT32 total_len  = 0,txed_len = 0;
	std::string data;
	Json::StyledWriter JsonWr;
	
	if(conn->status < RA_SOCK_CONNED){
		OSAL_trace(eRA, eError, "conn->status : %d is invalid",conn->status);
		return OSAL_ERROR;
	}
		
	ra_msg *jsonMsg = (ra_msg *)buff;
	jsonMsg->msg_type = type;
	jsonMsg->body_type = BODY_TYPE_JSON;
	jsonMsg->sn = htons((tcpMsgSeq++)%65535);
	data = JsonWr.write(value);
	jsonMsg->body_len = htons(data.length());
	memcpy(jsonMsg->body, data.c_str(), data.length());
	total_len = sizeof(ra_msg) + data.length();
	if((txed_len = send(conn->sock, (OSAL_CHAR *)jsonMsg ,total_len, 0 )) < 0){
		OSAL_trace(eRA, eError, "TX  msg :%d failed!",type);
		return OSAL_ERROR;
	}

	return txed_len;
}
static OSAL_INT32 hearbeat_to_router()
{
	tcp_conn_t *conn = raTcpConn;
	Json::Value hbMsg,hbMsgBak;
	OSAL_UINT32 bdin,bdout;
	
	if(conn->status != RA_REGISTED)
		return OSAL_ERROR;

	bdin = (rtppFlowStat[0].rxBytes - rtppFlowStat[1].rxBytes)/(1024 * 3);
	bdout = (rtppFlowStat[0].txBytes - rtppFlowStat[1].txBytes)/(1024 * 3);
	hbMsg["rtpp_ip"] = Json::Value(conn->self_ip_str);
	hbMsg["concurrency"] = Json::Value(rtppFlowStat[0].concurrency);
	hbMsg["ip_concurrency"] = Json::Value(rtppFlowStat[0].ipConcurrency);
	hbMsg["bandwidth_in"] = Json::Value(bdin);
	hbMsg["bandwidth_out"] = Json::Value(bdout);
	hbMsg["status"] = Json::Value(0);

	rtppFlowStat[1].rxBytes = rtppFlowStat[0].rxBytes;
	rtppFlowStat[1].txBytes = rtppFlowStat[0].txBytes;

	tx_tcp_msg_json(RA_HB_REQ,hbMsg);

	if(conn->bakFlag){
		if(!conn->bakStatus){
			hbMsgBak["rtpp_ip"] = Json::Value(conn->bak_ip_str);
			OSAL_trace (eRA, eDebug,"%s register_to_router %s ", conn->bak_ip_str,conn->router_ip_str);
			tx_tcp_msg_json(RA_REG_REQ,hbMsgBak);
		}else{
			hbMsgBak["rtpp_ip"] = Json::Value(conn->bak_ip_str);
			hbMsgBak["concurrency"] = Json::Value(rtppFlowStat[0].concurrency);
			hbMsgBak["ip_concurrency"] = Json::Value(rtppFlowStat[0].ipConcurrency);
			hbMsgBak["bandwidth_in"] = Json::Value(bdin);
			hbMsgBak["bandwidth_out"] = Json::Value(bdout);
			hbMsgBak["status"] = Json::Value(0);
			tx_tcp_msg_json(RA_HB_REQ,hbMsgBak);
		}
	}

	return OSAL_OK;
}

static void register_to_router()
{
	tcp_conn_t *conn = raTcpConn;
	Json::Value reg_body,regbak_body;
	
	if(conn->status != RA_SOCK_CONNED)
		return;
	
	reg_body["rtpp_ip"] = Json::Value(conn->self_ip_str);
	OSAL_trace (eRA, eDebug,"%s register_to_router %s ", conn->self_ip_str,conn->router_ip_str);
	tx_tcp_msg_json(RA_REG_REQ,reg_body);
	if(conn->bakFlag){
		regbak_body["rtpp_ip"] = Json::Value(conn->bak_ip_str);
		OSAL_trace (eRA, eDebug,"%s register_to_router %s ", conn->bak_ip_str,conn->router_ip_str);
		tx_tcp_msg_json(RA_REG_REQ,regbak_body);
	}
}

static bool parseJsonRegRsp(const std::string &input,tcp_conn_t *conn)
{
	bool parsingSuccessful = false;
	Json::Reader reader2; 
	Json::Value root;
	OSAL_INT32 ret;
	std::string rtppAddr;
	
	parsingSuccessful = reader2.parse(input,root);
	if(parsingSuccessful){
		Json::Value rtppip = root["rtpp"];
		Json::Value result = root["result"];
		rtppAddr = rtppip.asString();
		ret = atoi(result.asString().c_str());
	}else
		OSAL_trace(eRA, eError,"json parse fail ...");
	OSAL_trace (eRA, eDebug,"rtppAddr:%s,self_ip_str:%s",rtppAddr.c_str(),conn->self_ip_str);

	//debug
	/*
	if(ret == 0){
		OSAL_trace (eRA, eDebug, "[%s] register to router success!,result:%d",rtppAddr.c_str(),ret);
		conn->status = RA_REGISTED;	
		init_ra_nbr();
		conn->bakStatus = 1;
		//nbrCreateBakSocket();
	}
	*/
	if(strcmp(rtppAddr.c_str(),conn->self_ip_str) == 0){
		if(ret == 0){
			OSAL_trace (eRA, eDebug, "[%s] register to router success!,result:%d",rtppAddr.c_str(),ret);
			conn->status = RA_REGISTED;	
			init_ra_nbr();
		}else
			OSAL_trace (eRA, eError, "[%s] register to router failed!,result:%d",rtppAddr.c_str(),ret);
	}else if(conn->bakFlag && strcmp(rtppAddr.c_str(),conn->bak_ip_str) == 0){
		if(ret == 0){
			conn->bakStatus = 1;
			nbrCreateBakSocket();
		}
	}
		
	return parsingSuccessful;
}
void read_tcp_msg()
{
	OSAL_INT32 len = 0,result = -1;
	ra_msg *msg = NULL;
	tcp_conn_t *conn = raTcpConn;

	//while(len > 0){

	//}
	//memset(conn->rcv_buf,0x00,sizeof(conn->rcv_buf));
	len = recv(conn->sock, conn->rcv_buf+conn->rcv_len,  sizeof(conn->rcv_buf)-conn->rcv_len, 0);
	if(len < 0) {
		OSAL_trace(eRA, eError, "sock %d recv fail, %s(%d)", conn->sock,  strerror(errno), errno);
		close_tcp_sock();
		return;
	}
	if (len == 0) {
		OSAL_trace(eRA, eError, "tcp connection peer is closed, sock %d", conn->sock);
		close_tcp_sock();
		return;
	}
	conn->rcv_len += len;
	
DEAL_MESSAGE:
	msg = (ra_msg *)conn->rcv_buf;
	if (len < sizeof(ra_msg)) {
		OSAL_trace (eRA, eError, "RX msg len : %d is invalid",len);
		return;
	}
	if(conn->rcv_len < sizeof(ra_msg)) {
		OSAL_trace (eRA, eSys, "RX msg len : %d is not enough header len",conn->rcv_len);
		return ;
	}

	if ((conn->rcv_len - sizeof(ra_msg)) <  ntohs(msg->body_len)) {
		OSAL_trace (eRA, eSys, "RX msg len : %d is not enough body len",conn->rcv_len);
		return ;
	}
	
	OSAL_trace (eRA, eDebug,"RX TCP MSG,type:%d,bodyLen:%d,body:%s",msg->msg_type,htons(msg->body_len),(OSAL_CHAR *)msg->body);
	switch(msg->msg_type)
	{
		case RA_REG_RSP:
			parseJsonRegRsp((OSAL_CHAR *)msg->body,conn);
			break;
		case RA_HB_RSP:
			OSAL_trace(eRA, eDebug, "--->RX HB RSP");
			conn->hb_loss_cnt--;
			break;
		case RA_NB_LIST:
			nbrProcMsgNbList((OSAL_CHAR *)msg->body,ntohs(msg->body_len));
			break;
		default:
			break;
			
	}

	conn->rcv_len -= (sizeof(ra_msg) + ntohs(msg->body_len)); 
	if (conn->rcv_len > 0) {
		memmove(conn->rcv_buf, conn->rcv_buf+sizeof(ra_msg)+ntohs(msg->body_len), conn->rcv_len);
		goto DEAL_MESSAGE;	
	}
	
	//return OSAL_OK;
}


static OSAL_INT32 rx_tcp_msg(OSAL_INT32 sock_id, OSAL_INT32 evt)
{
	switch(evt){
		case FD_ACCEPT:
			//break;

		case FD_READ:
			OSAL_trace (eRA, eDebug,"rx_tcp_msg--->evt:%d,raTcpConn->sock:%d,sock_id:%d",evt,raTcpConn->sock,sock_id);
				if(raTcpConn->sock == sock_id)		
					read_tcp_msg();
			break;

		case FD_CLOSE:
			OSAL_trace (eRA, eDebug,"socket close, fd %d", sock_id);
			if(raTcpConn->sock == sock_id)
				close_tcp_sock();
			break;
		default:
			break;
	}
			
	return 0;
	
}

void tcp_connect_timeout()
{
	tcp_conn_t *conn = raTcpConn;
	OSAL_INT32 ret;

	switch (conn->status) {
		case RA_INVALID:
			create_tcp_sock();
			break;
		case RA_SOCK_INITED:
			//request for connect
			connect_to_router();
			conn->conn_times++;
			if(conn->conn_times == 3){
				close_tcp_sock();
			}
			break;
		case RA_SOCK_CONNED:			
			//request for register
			register_to_router();
			conn->conn_times = 0;
			break;
		case RA_REGISTED:
			//send hearbeat
			ret = hearbeat_to_router();
			if(ret == OSAL_OK)
				raTcpConn->hb_loss_cnt++;
			if(raTcpConn->hb_loss_cnt == 4) {
				close_tcp_sock();
			}
	}
}


void ra_timer_out(OSAL_msgHdr *pMsg)
{
	OSAL_timerMsgHdrT *pTimerMsg;
	pTimerMsg = (OSAL_timerMsgHdrT *) pMsg->pContent;
	OSAL_INT32 ret;

	if ( OSAL_NULL==pTimerMsg || sizeof(OSAL_timerMsgHdrT)!=pMsg->contentLen ){
	    OSAL_trace(eRA, eError, "Not a timer Message!");
	    return;
	}
	
	switch (pTimerMsg->param1) {
		case TIMER_TX_HB:
			ret = hearbeat_to_router();
			if(ret == OSAL_OK)
				raTcpConn->hb_loss_cnt++;
			if(raTcpConn->hb_loss_cnt == 4)
				close_tcp_sock();
			break;
		case TIMER_CALC_PING:
			nbrCalcTimeoutHd();
			break;
		case TIMER_TX_PING:
			nbrTxPingTimeoutHd();
			break;
		case TIMER_TCP_CONNECT:
			tcp_connect_timeout();
			break;
		default:
			OSAL_trace(eRA, eWarn, "not exsited TMR type.");
			break;
	}
}

static void recfg_pkt_intv()
{
	nbrResetTxPingTimer();
}
static void recfg_calc_intv()
{
	nbrResetCalcPingTimer();
}

void ra_rx_rtpp_stat(OSAL_msgHdr *pMsg)
{
	flowStat *pStat = (flowStat *)pMsg->pContent;
	if ( OSAL_NULL==pStat || sizeof(flowStat) != pMsg->contentLen ){
	    OSAL_trace(eRA, eError, "Not a timer Message!");
	    return;
	}

	rtppFlowStat[0].concurrency = pStat->concurrency;
	rtppFlowStat[0].ipConcurrency = pStat->ipConcurrency;
	rtppFlowStat[0].rxBytes = pStat->rxBytes;
	rtppFlowStat[0].txBytes = pStat->txBytes;
}

void ra_recfg(OSAL_msgHdr *pMsg)
{
	OSAL_trace(eRA, eDebug, "recfg : %d",pMsg->msgSubId);
	switch(pMsg->msgSubId)
	{		
		case RECFG_PKT_INTV:
			recfg_pkt_intv();
			break;
		case RECFG_CALC_INTV:
			recfg_calc_intv();
			break;
		default:
			OSAL_trace(eRA, eWarn, "unknow type of recfg.");
			break;
	}
	
}

void ra_send_agent_addr()
{
	OSAL_msgHdr mmsg;
	
	memset(&mmsg,0x00,sizeof(mmsg));
	mmsg.msgId = RTPP_AGENT_ADDR_SYN;
	mmsg.contentLen = strlen(raTcpConn->self_ip_str)+1;
	mmsg.pContent = raTcpConn->self_ip_str;
	OSAL_sendMsg(eNOTIFY,&mmsg);	
}

void ra_set_conn_addr(const OSAL_CHAR *ipaddr,OSAL_INT32 port)
{
	memset(raTcpConn->router_ip_str,0x0,sizeof(raTcpConn->router_ip_str));
	raTcpConn->router_port = 0;
	strcpy(raTcpConn->router_ip_str,ipaddr);
	raTcpConn->router_port = port;
	OSAL_trace (eRA, eDebug, "ipaddr:%s,port:%d",raTcpConn->router_ip_str,raTcpConn->router_port);
}

OSAL_INT32 ra_init(void)
{
	OSAL_INT32 ret;
	//OSAL_setTrace(eRA, eDebug);//for debug
	ConfigFile *cfg  = ConfigFile::GetInstance();
	//cfg->dump();//FOR debug

	init_tcp_connect();
	init_rts();
	
	std::string myAddr = cfg->getvalue<std::string>("agent_addr");
	strcpy(raTcpConn->self_ip_str,myAddr.c_str());
	std::string bakAddr = cfg->getvalue<std::string>("agent_addr_bak");
	if(bakAddr.length() > 0){
		strcpy(raTcpConn->bak_ip_str,bakAddr.c_str());
		raTcpConn->bakFlag = 1;
	}

	start_connect_timer();
	ra_init_shell();

	return OSAL_OK;
}

OSAL_INT32 ra_main(OSAL_msgHdr *msg_hdr)
{
	switch (msg_hdr->msgId) {
		case RA_MAIN_MSG:
			rx_tcp_msg(msg_hdr->msgSubId, msg_hdr->param);
			break;
		case RA_PING_MSG:
		case RA_PING_BAK_MSG:
			nbrRxPingMsg(msg_hdr->msgSubId);
			break;
		case eOsalSysMsgIdTimer:			
			ra_timer_out(msg_hdr);
			break;
		case RA_RECONFIG:
			ra_recfg(msg_hdr);
			break;
		case RTPP_AGENT_ADDR_SYN:
			ra_send_agent_addr();
			break;
		case RTPP_REPORT_STAT:
			ra_rx_rtpp_stat(msg_hdr);	
			break;
		default:
			OSAL_trace (eRA, eExcept, "Unknown msg id,don't process,drop it");
			break;
	}
	
	return OSAL_OK;
}

void ra_end(void)
{
	if(raTcpConn)
		osal_free(raTcpConn);
}



