#ifdef __cplusplus
extern "C"
{
#endif
#include "common.h"
#include "rtpp_common.h"
#include "rtpp_main.h"
#include "rtpp_session.h"
#include "rtpp_util.h"
#include "rtpp_mixer.h"
#include "directcall_fec.h"
#include "rtp_to_prtp.h"
#include "rtpp_record.h"
#include "rtpp_conference.h"

#include "rtpp_http_vm.h"


RtppGlobalsT RtppGlobals;
static OSAL_CHAR gbuf[RTPP_MSG_MAX_LEN];
OSAL_HHASH	conferenceHashTable;
pthread_mutex_t rtpp_conf_hashtable_lock;
OSAL_CHAR ghttpVmServerIp[MAX_IP_LEN] = "127.0.0.1";
OSAL_INT32 ghttpVmServerPort = 10088;
OSAL_CHAR ghttpVmCfgReloaded = 0;
OSAL_UINT32  RtppTime = 0; 
extern void rtpp_init_shell ();

OSAL_INT32 init_rtpp_cfg(OSAL_CHAR *buff, OSAL_INT32 lines)
{
	OSAL_CHAR *equ,*pch=NULL;
	OSAL_INT32 i = 0;
	OSAL_INT32 ip = 0;

    //printf("@@@@@@@@@%s\r\n",buff);
	equ = strchr(buff, '=');
	if(!equ){
		return -1;
	}
	*equ = 0;
	equ++;

	if(!strcmp(buff, RTPP_LABEL_COMMAND)){
		strncpy(RtppGlobals.command_socket,equ,RTPP_COMMAND_SOCKET_LEN-1);
	}
		
	if(!strcmp(buff, RTPP_LABEL_HOST_IP)){
		pch = strtok(equ, "/");
		while(NULL != pch) {
			strncpy(RtppGlobals.localip[i],pch,15);
			if(inet_pton(AF_INET,pch,&ip) != 1){
				OSAL_trace(eRTPP, eSys,"host ip %s is invalid", pch);
				exit(1);
			}
			OSAL_trace(eRTPP, eSys,"local host[%d]: %s", i,RtppGlobals.localip[i]);
			i++;
			if(i == RTPP_MAX_RTPC_NUM) break;
			pch = strtok(NULL, "/");
		}
		RtppGlobals.localipnum = i;
	}
	else if(strstr(buff, "RTPP_HTTP_VM_SERVER_IP")) //-s
	{
        strncpy(ghttpVmServerIp,(buff+strlen("RTPP_HTTP_VM_SERVER_IP=")),sizeof(ghttpVmServerIp));
        printf("ghttpVmServerIp %s\r\n",ghttpVmServerIp);
	}
	else if(strstr(buff, "RTPP_HTTP_VM_SERVER_PORT")) //-s
	{
        ghttpVmServerPort = atoi(buff + strlen("RTPP_HTTP_VM_SERVER_PORT="));
        printf("ghttpVmServerPort %d\r\n",ghttpVmServerPort);
	}
	else if(!strcmp(buff, RTPP_LABEL_TTL_MODE)){
		OSAL_trace(eRTPP, eSys,"rtpp time mode:%s",equ);
		RtppGlobals.ttlmode = atoi(equ);
	}else if(!strcmp(buff, RTPP_LABEL_TIMEOUT_LEN)){
		RtppGlobals.timeout = atoi(equ);
		OSAL_trace(eRTPP, eSys,"rtpp time out:%s",equ);
	}else if(!strcmp(buff, RTPP_LABEL_RTPC_IP)){
		pch = strtok(equ, "/");
		while(NULL != pch) {
			if(inet_pton(AF_INET,pch,&ip) != 1){
				OSAL_trace(eRTPP, eSys,"rtpc ip %s is invalid", pch);
				exit(1);
			}
			RtppGlobals.rtpc[i] = ip;
			strncpy(RtppGlobals.rtpcip[i],pch,15);
			OSAL_trace(eRTPP, eSys,"remote rtpc[%d]: %s", i,RtppGlobals.rtpcip[i]);
			i++; 
			if(i == RTPP_MAX_RTPC_NUM) break;
			pch = strtok(NULL, "/");
		}
		RtppGlobals.rtpcnum= i;
	}
	else if(!strcmp(buff, RTPP_LABEL_RECORD_DIR))
	{
		strncpy(RtppGlobals.record_dir, equ, RTPP_MAX_RECORD_DIR);
		RtppGlobals.record_dir[RTPP_MAX_RECORD_DIR-1] = '\0';
	}else if(!strcmp(buff, RTPP_LABEL_LOSS_RC_MODE)){
		RtppGlobals.rc_flag = atoi(equ);
	}else if(!strcmp(buff, RTPP_LABEL_JT_FLAG)){
		RtppGlobals.jt_flag= atoi(equ);
	}
    else
    {
        printf("can not parase string %s \r\n", buff);
    }
	
	return OSAL_OK;
}

void rtpp_init_stat_timer()
{
	OSAL_timerMsgHdrT timerMsg;

	timerMsg.moduleId = eRTPP;
	timerMsg.timerMsgType = eOsalSysMsgIdTimer;
	timerMsg.param1 = RTPP_TIME_STAT;
	RtppGlobals.stat_timer = OSAL_stimerStart(&timerMsg, 3*1000);
}

void rtpp_init_record()
{
	DIR *pdir = OSAL_NULL;

	if(strlen(RtppGlobals.record_dir) > 0){
		if(RtppGlobals.record_dir[strlen(RtppGlobals.record_dir)-1] != '/')
			strcat(RtppGlobals.record_dir, "/");
		if((pdir=opendir(RtppGlobals.record_dir)) == OSAL_NULL) {
			if (errno == ENOENT){
				char cmd[256] = {0};
				sprintf(cmd, "mkdir -p %s", RtppGlobals.record_dir);
				system(cmd);
				OSAL_trace(eRTPP, eSys,"create record dir: %s", RtppGlobals.record_dir);	
			}
		}
		else{
			OSAL_trace(eRTPP, eSys,"record dir: %s", RtppGlobals.record_dir);
			closedir(pdir);
		}

	}
	else{
		if((pdir=opendir("/data/record/")) == OSAL_NULL) {
			if (errno == ENOENT){
				char cmd[256] = {0};
				sprintf(cmd, "mkdir -p %s", "/data/record/");
				system(cmd);
				strcpy(RtppGlobals.record_dir, "/data/record/");
				OSAL_trace(eRTPP, eSys,"create record dir: %s", RtppGlobals.record_dir);	
			}
		}
		else{
			strcpy(RtppGlobals.record_dir, "/data/record/");
			OSAL_trace(eRTPP, eSys,"record dir: %s", RtppGlobals.record_dir);
			closedir(pdir);
		}
	}

}

void rtpp_get_record_dir(OSAL_CHAR *buf)
{
	if(!buf)
		return;

	strcpy(buf,RtppGlobals.record_dir);
}

OSAL_CHAR rtpp_get_rc_flag()
{
	return RtppGlobals.rc_flag;
}

void rtpp_set_rc_flag(OSAL_CHAR flag)
{
	RtppGlobals.rc_flag = flag;
}

OSAL_INT32 rtpp_init_mix(void)
{
	/* create ip hash table*/
	conferenceHashTable = OSAL_hashConstruct(MAX_CONFERENCE_NUM, MAX_CONFERENCE_NUM, MAX_COOKIE_LEN, sizeof(struct conference_info_t), "conferenceHashTable");
	if ( OSAL_NULL == conferenceHashTable )
	{
		OSAL_trace( eRTPP, eError, "create conference hash table failed.");
		return OSAL_ERROR;
	}
	pthread_mutex_init(&rtpp_conf_hashtable_lock, NULL);

	if (Mixer_init() < 0)
	{
		OSAL_trace( eRTPP, eError, "mixer init err.");
		return OSAL_ERROR;
	}
	mixer_cb_vtable_t cb_vtable;
	cb_vtable.send_cb = rtpp_mixer_send_media_cb;
	cb_vtable.log_cb = rtpp_mixer_trace_log_cb;
	//cb_vtable.log_cb = NULL;
	Mixer_callback_vtable(&cb_vtable);

	unsigned int mask = kMixer_TraceReport|kMixer_TraceError;
	//unsigned int mask = kMixer_TraceReport|kMixer_TraceWarning|kMixer_TraceInfo; //kMixer_TraceError;  kMixer_TraceReport;//kMixer_TraceNone ;//|kMixer_TraceWarning|kMixer_TraceStream|kMixer_TraceApiCall;
	//unsigned int mask = kMixer_TraceInfo|kMixer_TraceWarning|kMixer_TraceError|kMixer_TraceApiCall|kMixer_TraceDebug|kMixer_TraceReport;
	
	Mixer_trace_log_level(mask);
	OSAL_trace( eRTPP, eSys, "mixer init ok.");

	return OSAL_OK;
}

//´Ë´úÂëÓÃÓÚ²âÊÔrtppÖ®¼äµÄFEC¹¦ÄÜ£¬³õÊ¼»¯Á½×é¶Ë¿Ú
//Ò»×éÓÃÓÚ×ª·¢°ü
//ÁíÒ»×é¶Ë¿ÚÓÃÓÚFEC°ü
OSAL_INT32 rtpp_init_test_instance(void)
{
	if(MODULE_SELF()->modid == eRTPP1)
	{
		OSAL_timerMsgHdrT tt = {0};
		tt.param1 = Init_TestInstance_Timer;
		tt.moduleId = eRTPP1;
		RtppGlobals.htest.t = OSAL_stimerUseOneTime(&tt, 5000);
	}

	return 0;
}

OSAL_INT32 rtpp_init_test_instance_func(void)
{
	rtpp_session_t *ss = NULL;
	OSAL_CHAR callid[RTPP_MAX_CALLID_LEN] = {0};
	OSAL_CHAR fromtag[RTPP_MAX_TAG_LEN] = {0};
	OSAL_CHAR totag[RTPP_MAX_TAG_LEN] = {0};
	OSAL_CHAR  cookie[RTPP_MAX_COOKIE_LEN] = {0};

	OSAL_INT32 mod_id = eRTPP1;       
	OSAL_INT32 pt[2] = {106, 18};	
	OSAL_INT32 iIndex = 0;
	OSAL_CHAR lFecModel = -1,RFecModel = -1;
	OSAL_INT32 linitip = 0,rinitip = 0;
	OSAL_INT32 /*lPort = 0,*/rPort = 0;
	OSAL_INT32 lAsy = 0,rAsy = 0;

	OSAL_INT32 res = 0;

	if(inet_pton(AF_INET,"127.0.0.1",&linitip) != 1){
		printf( "error remote rtpp ip\n");
		return -1;
	}

	if(inet_pton(AF_INET,"127.0.0.1",&rinitip) != 1){
		printf( "error remote rtpp ip\n");
		return -1;
	}
	for(iIndex = 0; iIndex < 2; iIndex++){
		snprintf(callid, RTPP_MAX_CALLID_LEN, SPECACLL_STR_CALLID,  iIndex,iIndex);
		snprintf(fromtag, RTPP_MAX_TAG_LEN, SPECCALL_STR_CALLER,  iIndex);
		snprintf(totag, RTPP_MAX_TAG_LEN, SPECCALL_STR_CALLEE,  iIndex);
		snprintf(cookie, RTPP_MAX_COOKIE_LEN, SPECCALL_STR_COOKIE,  iIndex,iIndex);
		ss = &RtppGlobals.htest.ss[iIndex];
		ss->right.audio[0].pt = pt[1];
		ss->left.audio[0].pt = pt[0];     
		ss->mod_id = mod_id;
		ss->ttlmode = RtppGlobals.ttlmode;
		ss->timeout = RtppGlobals.timeout;
		strcpy(ss->cookie,cookie);
		strncpy(ss->f_tag,fromtag,RTPP_MAX_TAG_LEN-1);
		strncpy(ss->to_tag,totag,RTPP_MAX_TAG_LEN-1);
		printf("New special call%s (%d) :%d [%s-%s]\n",callid,mod_id,iIndex,ss->f_tag,ss->to_tag);
		ss->inuse = 1;
		strcpy(ss->call_id,callid);
		res = rtpp_pop_port(RTPP_BRANCHE_RIGHT, 0, mod_id,0,rinitip,rPort,0,0,lAsy,0, RFecModel, ss);
		if(res < 0){
			printf("spec call alloc right port fail\n");
			return -1;
		}
		printf("Spec U1(%d) [%s->%s]alloc audio %d fd:%d\n",mod_id,ss->f_tag,ss->to_tag,ss->right.audio[0].p->port,ss->right.audio[0].p->fd);
		res = rtpp_pop_port(RTPP_BRANCHE_LEFT,0, mod_id,0,linitip,rPort,0,0,rAsy,0,lFecModel, ss);
		if(res < 0){
			printf("spec call alloc left port fail\n");
			return -1;
		}
		printf("Spec U2(%d) [%s->%s]alloc audio %d fd:%d\n",mod_id,ss->f_tag,ss->to_tag,ss->left.audio[0].p->port,ss->left.audio[0].p->fd);
		
		ss->left.audio[0].trans= &ss->right.audio;
		ss->right.audio[0].trans= &ss->left.audio;
		ss->left.video[0].trans= &ss->right.video;
		ss->right.video[0].trans= &ss->left.video;
		//init fec
		if(iIndex){
			if(fec_init(&(ss->fec_inst)) < 0){
				printf("spec call use fec fail\n");
				return OSAL_ERROR;
			}
			else
			{
				printf("fec_inst is %p\n", ss->fec_inst);
			}
		}
		ss->vflag = 0;
		ss->tsc_flag = 0;
		ss->fec_flag = iIndex;
		ss->record_flag = 0;
		ss->finish = 0;
	}
	return OSAL_OK;
}

OSAL_INT32 rtpp_init (void)
{
	if(init_cfg(CONFIG_FILE, init_rtpp_cfg) != OSAL_OK) {
		OSAL_trace (eRTPP, eError, "init cfg file failed.");
		return OSAL_ERROR;
	} 

	if(rtpp_session_init() != OSAL_OK) {
		OSAL_trace (eRTPP, eError, "init rtpp session failed.");
		return OSAL_ERROR;
	}

	if(init_controlfd() != OSAL_OK) {
		OSAL_trace (eRTPP, eError, "init control fd failed.");
		return OSAL_ERROR;
	}

	if(init_port_table() != OSAL_OK) {
		OSAL_trace (eRTPP, eError, "init port table failed.");
		return OSAL_ERROR;
	}

	if(rtpp_init_mix() != OSAL_OK) {
		OSAL_trace (eRTPP, eError, "init mix failed.");
		return OSAL_ERROR;
	}
	RtppGlobals.historypercent = 70;

	rtpp_init_record();
	rtpp_init_shell ();
	rtpp_init_stat_timer();
	//init rtpp seed
	srand(time(0));
	OSAL_trace(eRTPP, eSys, "** Init ok! **");
	OSAL_trace(eRTPP, eSys, "*****************************************************");	
	return OSAL_OK;
}

OSAL_INT32 rtpp_get_threadId(OSAL_CHAR *s,OSAL_INT32 len)
{
	OSAL_INT32 i;
	OSAL_INT32 res = 0;
	
	for(i = 0;i < len;i++){
		res += s[i];
	}
	return ((res%RTPP_PTHREAD_NUM) + eRTPP1);
}



static OSAL_INT32 rtpp_n_update(OSAL_CHAR *msg,OSAL_INT32 len,OSAL_INT32 fip,OSAL_UINT16 fport)
{	
	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_INT32 argc;
	OSAL_msgHdr mimsg;

	command_parse(msg,len,argv,&argc);
	
	memset(&mimsg,0,sizeof(OSAL_msgHdr));
	
	if(3 == argc){
		if(check_ip_list(argv[2],'/') < 0)
			return -1;
	    mimsg.param = eUPDATE_IPS;
		mimsg.contentLen = strlen(argv[2])+1;
	 	mimsg.pContent = (void*)argv[2];
	}else{	 
		mimsg.param = eCLEAR_IPS;
	}
	
	rtpp_reply_ok(argv[0],fip,fport);

	mimsg.sender = eRTPP;
	mimsg.msgId = PING_CONTROL_RTPP_IPS;
	OSAL_sendMsg(ePING, &mimsg);
		
	return 0;
}

static OSAL_INT32 rtpp_g_update(OSAL_CHAR *msg,OSAL_INT32 len,OSAL_INT32 fip,OSAL_INT32 fport)
{
#define OSAL_MAX_MI_MSG_CONTENT_LEN 1024
	
	OSAL_INT32 i = 0;
	OSAL_CHAR *p = NULL;
	OSAL_CHAR *q = NULL;
	OSAL_CHAR temp[OSAL_MAX_MI_MSG_CONTENT_LEN] = {0};
	struct sockaddr_in from_addr;

	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_INT32 argc;
	OSAL_msgHdr mimsg;
	
	command_parse(msg,len,argv,&argc);
	
	memset(&mimsg,0,sizeof(OSAL_msgHdr));
	
	if(3 == argc){
		if(check_ip_list(argv[2],'/') < 0)
			return -1;

		memset(&mimsg,0,sizeof(OSAL_msgHdr));
		mimsg.sender = eRTPP;
		mimsg.msgId = PING_CONTROL_GW_IPS;
		if(argv[2] != OSAL_NULL)
		{
			memset(&from_addr, 0, sizeof(from_addr));
			from_addr.sin_addr.s_addr = fip;
			OSAL_trace(eRTPP, eInfo, "recv gwlist from rtpc:%s, list:%s",inet_ntoa(from_addr.sin_addr), argv[2]);
			OSAL_CHAR tmpIP[32] = {0};
			OSAL_CHAR *pch = strchr(argv[2], '/');
			OSAL_CHAR *pch_bak = argv[2];
			while(pch) {
				strncpy(tmpIP, pch_bak, pch-pch_bak);
				if(inet_addr(tmpIP) == INADDR_NONE)
					return 2;
				pch_bak = ++pch;
				pch = strchr(pch, '/');
				memset(tmpIP, 0, sizeof(tmpIP));
			}
			if(pch_bak && strlen(pch_bak)) {
				strcpy(tmpIP, pch_bak);
				if(inet_addr(tmpIP) == INADDR_NONE)
					return 2;
			}
		
			q = argv[2];
			while(strlen(q) > 0)
			{
				for(i=0;i<50;i++)
				{
					if((p = strchr(q, '/')) != NULL)
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
	
				mimsg.param = eUPDATE_IPS;
				mimsg.contentLen = strlen(temp) + 1;
				mimsg.pContent = temp;
				OSAL_trace(eRTPP, eDebug, "send gwlist from RTPP to PING,which content is %s", mimsg.pContent);
				//send gwlist to ePING
				if(OSAL_sendMsg(ePING, &mimsg) != OSAL_OK) {
					OSAL_trace(eRTPP, eError, "send pipe msg to PING err.");
					return 11;
				}
				memset(temp , 0, sizeof(temp));
			}
		
		
		}
	}else{	 
		mimsg.param = eCLEAR_IPS;
	}
	rtpp_reply_ok(argv[0],fip,fport);
		
	return 0;
}

void rtpp_send_msg_to_notify(OSAL_INT32 msgId,OSAL_CHAR *msg,OSAL_INT32 param)
{
	OSAL_msgHdr mmsg;
	OSAL_INT32 len;
	
	memset(&mmsg,0x00,sizeof(mmsg));
	len = strlen(msg);
	mmsg.msgId = msgId;
	mmsg.param = param;
	mmsg.param2 = 9988;
	mmsg.contentLen = len+1;
	mmsg.pContent = msg;
	OSAL_sendMsg(eNOTIFY,&mmsg);	
}

static OSAL_INT32 rtpp_msg_dispatch(OSAL_CHAR *msg,OSAL_INT32 len,OSAL_INT32 ip,OSAL_INT32 port)
{	
	OSAL_CHAR *dot = NULL;
	OSAL_CHAR *da = NULL;
	OSAL_CHAR *blank;
	OSAL_INT32 di;
	OSAL_msgHdr mimsg;

	memset(&mimsg,0x00,sizeof(mimsg));

	if((*msg|32) == 'g'){
		rtpp_g_update(msg,len,ip,port);
		return 0;
	}else if((*msg|32) == 'n'){
		rtpp_n_update(msg,len,ip,port);
		return 0;
	}
	
	//U202.105.136.108@280@280.552
	blank = strchr(msg,' ');
	if(blank){
		*blank = 0;
		dot = strrchr(msg,'@');
		da = strchr(msg,'@');
		*blank = ' ';
	}
	if(!dot || !da || (da == dot)){
		OSAL_trace (eRTPP, eError, "msg no dot or da:%s",msg);
		return -1;
	}
	*dot = 0;
	da++;
	OSAL_trace (eRTPP, eDebug, "key:%s",da);
	di = rtpp_get_threadId(da,dot-da);
	mimsg.sender = eRTPP;
	mimsg.msgId= RTPP_DISPATCH_MSG;
	mimsg.msgSubId= di;
	mimsg.param = ip;
	mimsg.param2 = port;
	mimsg.pContent = msg;
	mimsg.contentLen = len+1;
	*dot = '@';

	OSAL_sendMsg(di,&mimsg);
	return OSAL_OK;
}

OSAL_INT32 rtpp_command_rx(OSAL_msgHdr *pMsg)
{
	OSAL_INT32 fd = pMsg->msgSubId;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	OSAL_CHAR ip[RTPP_MAX_IP_LEN];
	OSAL_INT32 port;
	OSAL_INT32 len = 0;
	
	if((len = recvfrom(fd,gbuf,RTPP_MSG_MAX_LEN - 1,0,(struct sockaddr *)&addr,&addrlen)) < 0){
		OSAL_trace (eRTPP, eError, "recv err %s %d",strerror(errno),errno);
		return -1;
	}
	
	gbuf[len] = 0;

	strcpy(ip,inet_ntoa(addr.sin_addr));
	port = ntohs(addr.sin_port);
	
	OSAL_trace(eRTPP, eInfo, "recv command (%s) from ip:%s port:%d",gbuf,ip,port);

	if(rtpp_ip_check(addr.sin_addr.s_addr) < 0){
		OSAL_trace (eRTPP, eError, "msg from ip %s check failed",ip);
		return -1;
	}
	
	rtpp_msg_dispatch(gbuf,len,addr.sin_addr.s_addr,addr.sin_port);
		  
	return 0;
}
void rtpp_stats_report()
{
	OSAL_msgHdr msg = {0};
	msg.msgId = RTPP_REPORT_STAT;
	msg.contentLen = sizeof(RttpPktStat);
	RtppGlobals.stats_.concurrency = rtpp_hash_tbl.used.counter;
	RtppGlobals.stats_.ipConcurrency = table[0].used;
	msg.pContent = (void *)&RtppGlobals.stats_;
	OSAL_sendMsg(eRA,&msg);
}
void rtpp_timer_out(OSAL_msgHdr *pMsg)
{
	OSAL_timerMsgHdrT *pTimerMsg;
	pTimerMsg = (OSAL_timerMsgHdrT *) pMsg->pContent;
	OSAL_INT32 ret;

	if ( OSAL_NULL==pTimerMsg || sizeof(OSAL_timerMsgHdrT)!=pMsg->contentLen ){
	    OSAL_trace(eRTPP, eError, "Not a timer Message!");
	    return;
	}
	
	switch (pTimerMsg->param1) {
		case RTPP_TIME_STAT:
			rtpp_stats_report();	
			break;
		default:
			OSAL_trace(eRTPP, eWarn, "not exsited TMR type.");
			break;
	}
}

OSAL_INT32 rtpp_main(OSAL_msgHdr *pMsg)
{
	switch (pMsg->msgId){
	  	case RTPP_UDP_COMMAND:
			rtpp_command_rx (pMsg);
		 	break;	
		case eOsalSysMsgIdTimer:
			rtpp_timer_out(pMsg);
			break;
	  	default:
		  	OSAL_trace(eRTPP, eWarn, "invalid msg type[%d].",pMsg->msgId);
		  break;
	}

	return OSAL_OK;	
}

void rtpp_end (void)
{
/*
	if(!RtppGlobals.initialized)   {
		OSAL_trace(eRTPP, eError, "RTPP isn't initialized");
		return;
	}
*/

	pthread_mutex_destroy(&rtpp_conf_hashtable_lock);

}

OSAL_INT32 rtpp_work_init (void)
{
	rtpp_init_test_instance ();
	return OSAL_OK;
}

static OSAL_INT32 __lost2level(OSAL_UINT32 lost)
{
	if(lost == 0) return 0;
	else if(lost<500) return 1;
	else if(lost<1000) return 2;
	else if(lost<3000) return 3;
	else if(lost<5000) return 4;
	return 5;
}

static OSAL_INT32 __calc_smooth_lost(port_info_t *refer, OSAL_UINT32 lost)
{
	refer->fec_local_last_smooth_lost = refer->fec_local_smooth_lost;
	if(lost>refer->fec_local_last_smooth_lost){
		if(!refer->fec_local_last_smooth_lost)
			refer->fec_local_smooth_lost = 10000;
		else refer->fec_local_smooth_lost = lost;
	}else{
		refer->fec_local_smooth_lost = (refer->fec_local_last_smooth_lost*RtppGlobals.historypercent+lost*(100-RtppGlobals.historypercent))/100;
	}
	OSAL_trace(eRTPP, eInfo, "ssrc:%x last lost smooth:%0.4f,current lost smooth:%0.4f",refer->packet.ssrc,refer->fec_local_last_smooth_lost/10000.0,refer->fec_local_smooth_lost/10000.0);
	return 0;
}

static OSAL_UINT16 inline __realtime_lost_calc__(port_info_t *refer,OSAL_INT32 nCalcType)
{	
	OSAL_UINT16 lost = 0;
	OSAL_UINT32 expect_count =0;
	OSAL_CHAR ipbuf[100] = {0};
	OSAL_CHAR flagbuf[10] = {0};
	OSAL_CHAR reportflagbuf[30] = {0};
	realtime_lost_entry *stats_entry = NULL;
	OSAL_CHAR logbuf[4096] = {0};
	if (!refer)
		return 0xffff;

	if(nCalcType == RealTime_Lost_Fec)
	{
		stats_entry = &refer->realtime_lost_fec;
		memcpy(flagbuf,FLAG_STR_FEC,strlen(FLAG_STR_FEC));
		memcpy(reportflagbuf,FLAG_STR_FEC_REPORT,strlen(FLAG_STR_FEC_REPORT));
	}
	else if(nCalcType == RealTime_Lost)
	{
		stats_entry = &refer->realtime_lost;
		memcpy(flagbuf,FLAG_STR_REALTIME,strlen(FLAG_STR_REALTIME));
		memcpy(reportflagbuf,FLAG_STR_REALTIME_REPORT,strlen(FLAG_STR_REALTIME_REPORT));
	}
	else if(nCalcType == RealTime_Lost_Rtcp)
	{
		stats_entry = &refer->realtime_lost_rtcp;
		memcpy(flagbuf,FLAG_STR_RTCP,strlen(FLAG_STR_RTCP));
		memcpy(reportflagbuf,FLAG_STR_RTCP_REPORT,strlen(FLAG_STR_RTCP_REPORT));
	}
	else
	{
		OSAL_trace(eRTPP, eError, "Unknow calc type:%d!",nCalcType);
		return 0xffff;
	}
	stats_entry->calc_count ++;
       
	expect_count = stats_entry->current_seq -stats_entry->last_calc_seq + 1;
	OSAL_trace(eRTPP, eInfo, "%s last_calc_req:%d, last_calc_ssrc:%x current_seq %d,rcv_count:%d,expect_count:%d",
                flagbuf,stats_entry->last_calc_seq, stats_entry->last_calc_ssrc, stats_entry->current_seq,
                stats_entry->rcv_count,expect_count);
	if(0 >= expect_count){
		OSAL_trace(eRTPP, eError, "[expect_count<=0]%s last_calc_req:%d, last_calc_ssrc:%x current_seq %d,rcv_count:%d,expect_count:%d",
					flagbuf,stats_entry->last_calc_seq, stats_entry->last_calc_ssrc, stats_entry->current_seq,
					stats_entry->rcv_count,expect_count);
		return 0xffff;
	}

	if(0 > expect_count - stats_entry->rcv_count){
		OSAL_trace(eRTPP, eError, "[expect_count<rcv_count]%s last_calc_req:%d, last_calc_ssrc:%x current_seq %d,rcv_count:%d,expect_count:%d",
					flagbuf,stats_entry->last_calc_seq, stats_entry->last_calc_ssrc, stats_entry->current_seq,
					stats_entry->rcv_count,expect_count);
		return 0xffff;
	}
	
	lost = (expect_count - stats_entry->rcv_count )*10000/expect_count;

	if(nCalcType == RealTime_Lost_Rtcp){
		refer->fec_local_last_lost = refer->fec_local_lost;
		refer->fec_local_lost = lost;
		__calc_smooth_lost(refer,lost);
		refer->recv_lost_calc_finish = 1;
	}
	
	if (lost > 0){ //only remeber lost > 0 
		stats_entry->rt_lostrate[stats_entry->rt_index % REALLOST_SLOT_NUM].lost = lost;
		stats_entry->rt_lostrate[stats_entry->rt_index % REALLOST_SLOT_NUM].ts = (time(OSAL_NULL))&0x7fffffff;
		stats_entry->rt_index ++;
		stats_entry->total_lost+=lost;
	}
	memset(ipbuf,0,sizeof(ipbuf));
	inet_ntop(AF_INET,&refer->fip,ipbuf,sizeof(ipbuf));
	
	if (lost  >= 500) {
		if(nCalcType != RealTime_Lost_Rtcp){
			OSAL_trace(eRTPP, eSys, "%s %s:%d to %s:%d %s to %s rtp_stream:%x real_lost:%.4f smooth_lost:%.4f history_pri:%d calu_time:%llu calu_reason:%s",
			reportflagbuf,ipbuf, ntohs(refer->fport), RtppGlobals.localip[refer->p->index], refer->p->port, 
			refer->ss->f_tag,refer->ss->to_tag , stats_entry->last_calc_ssrc, lost/10000.0,refer->fec_local_smooth_lost/10000.0,RtppGlobals.historypercent,
			refer->packet.recv_time,calureason2str(refer->calu_value));
		}else{
			sprintf(logbuf, "%s %s:%d to %s:%d %s to %s rtp_stream:%x real_lost:%.4f smooth_lost:%.4f history:%d time:%llu c:%s",
			reportflagbuf,ipbuf, ntohs(refer->fport), RtppGlobals.localip[refer->p->index], refer->p->port, 
			refer->ss->f_tag,refer->ss->to_tag , stats_entry->last_calc_ssrc, lost/10000.0,refer->fec_local_smooth_lost/10000.0,RtppGlobals.historypercent,
			refer->packet.recv_time,calureason2str(refer->calu_value));
			OSAL_trace(eRTPP, eInfo, "%s",logbuf);
			//µ±Ç°Ö»ÉÏ±¨¶ª°üÂÊ´óÓÚ5%µÄÇé¿ö
			rtpp_send_msg_to_notify(RTPP_REPORT_LOG,logbuf,refer->ss->from_ip);
		}
	}else{
		sprintf(logbuf, "%s [%s:%d] to [%s:%d]  [%s] to [%s] rtp stream [%x] realtime lost rate:%.4f",
				flagbuf,ipbuf, ntohs(refer->fport), RtppGlobals.localip[refer->p->index], refer->p->port, 
				refer->ss->f_tag,refer->ss->to_tag, stats_entry->last_calc_ssrc, lost/10000.0);
		OSAL_trace(eRTPP, eInfo,"%s",logbuf);
		//rtpp_send_msg_to_notify(RTPP_REPORT_LOG,logbuf,refer->ss->from_ip);
	}

	if(lost >= 10000) {
		OSAL_trace(eRTPP, eWarn, "Wrong!!!%s [%s:%d] to [%s:%d]  [%s] to [%s] rtp stream [%x] realtime lost rate:%.4f  last_seq:%d  curr_seq:%d, rcv_num:%d",
		flagbuf,ipbuf, ntohs(refer->fport), RtppGlobals.localip[refer->p->index], refer->p->port, 
		refer->ss->f_tag,refer->ss->to_tag , stats_entry->last_calc_ssrc, lost/10000.0,
		stats_entry->last_calc_seq, stats_entry->current_seq, stats_entry->rcv_count);
	}

	return lost;

}

static void __init_real_lost_buf(port_info_t *refer,realtime_lost_entry *stats_entry)
{
	stats_entry->last_calc_systs = refer->packet.recv_time;
	stats_entry->last_calc_ts = refer->packet.ts;
	stats_entry->last_calc_seq = refer->packet.seq;
	stats_entry->last_calc_ssrc = refer->packet.ssrc;;
	stats_entry->current_seq = refer->packet.seq;
	stats_entry->rcv_count  = 1;
	memset(stats_entry->seq_map,0,sizeof(stats_entry->seq_map));
	stats_entry->seq_map[0] = TRUE;
}

void rtpp_jt_push_slot(port_info_t *refer,OSAL_CHAR *buf)
{
	OSAL_INT32 index;
	
	if(!refer || !buf){
		OSAL_trace(eRTPP, eError,"rtpp_jt_push_slot failed!");
		return;
	}

	if(!refer->jt_calc){
		return;
	}
	
	index = refer->packet.seq % JT_SLOT_NUM;
	OSAL_trace(eRTPP, eDebug,"seq:%d,index:%d\n",refer->packet.seq,index);
	if(refer->jt.slot[0].flag == 0)
		refer->jt.jt_offset = index;
	index -= refer->jt.jt_offset;
	if(index < 0 || index > JT_SLOT_NUM - 1)
		return;
	refer->jt.slot[index].flag = 1;
	refer->jt.slot[index].rx_time = refer->packet.recv_utime /1000.0;
	refer->jt.slot[index].tx_time = refer->packet.ts;
}

void rtpp_ssrc_statics(port_info_t *refer)
{
	OSAL_INT32 i =  0;
	
	for(i = refer->ssrc_num -1; i >= 0;i--){
		if(refer->ssrc[i].ssrc == refer->packet.ssrc
			&&refer->ssrc[i].fip== refer->fip
			&&refer->ssrc[i].fport== refer->fport){
			refer->ssrc[i].te = refer->packet.recv_time/1000;
			refer->ssrc[i].recv++;
			return;
		}
	}
	
	if(SSRC_SNAP_NUM == refer->ssrc_num){
		refer->ssrc_ful = 1;
	}else{
		refer->ssrc[refer->ssrc_num].ssrc = refer->packet.ssrc;
		refer->ssrc[refer->ssrc_num].fip = refer->fip;
		refer->ssrc[refer->ssrc_num].fport= refer->fport;
		refer->ssrc[refer->ssrc_num].ts = refer->packet.recv_time/1000;
		refer->ssrc[refer->ssrc_num].te = refer->packet.recv_time/1000;
		refer->ssrc[refer->ssrc_num].recv++;
		refer->ssrc_num++;
	}
	return;
}

void rtpp_ssrc_end(port_info_t *refer)
{
	OSAL_INT32 i =  0;
	OSAL_CHAR ipbuf[20] = {0};
	struct tm tts1 = {0};
	struct tm tts2 = {0};
	OSAL_CHAR buf[4000] = {0};
	OSAL_INT32 len = 0;

	len = sprintf(buf,"FLAG_STR_SNAP_SSRC %s to %s tatal:%d full:%d %clist:[ ", 
		refer->ss->f_tag,refer->ss->to_tag,refer->ssrc_num,refer->ssrc_ful,refer->va_flag==1?'l':'r');
	
	for(i = 0; i <refer->ssrc_num;i++){
		inet_ntop(AF_INET,&refer->ssrc[i].fip,ipbuf,sizeof(ipbuf));	
		localtime_r(&refer->ssrc[i].ts, &tts1);
		localtime_r(&refer->ssrc[i].te, &tts2);
		len+=sprintf(buf+len, "ssrc:%x from:%s:%d count:%d start:%2.2u:%2.2u:%2.2u to:%2.2u:%2.2u:%2.2u ", 
			refer->ssrc[i].ssrc,ipbuf,ntohs(refer->ssrc[i].fport),refer->ssrc[i].recv,
			tts1.tm_hour, tts1.tm_min, tts1.tm_sec,
			tts2.tm_hour, tts2.tm_min, tts2.tm_sec);
	}
	sprintf(buf+len,"]");
	OSAL_trace(eRTPP, eSys,buf);
	return;
}

void rtpp_jt_calc(port_info_t *refer)
{
	OSAL_UINT32 i,j;
	static OSAL_CHAR start = 1;
	double transit = 0.0,deltaTransit = 0.0;
    static double jitter = 0.0,lastTransit = 0.0;
    OSAL_CHAR reportflagbuf[30] = {0};   
    OSAL_CHAR ipbuf[100] = {0};
    struct jt_ret *res = NULL;
    
	if(!refer)
		return;
	
	if(!refer->jt_calc){
		return;
	}

	for(i = 0 , j = 1 ; j < JT_SLOT_NUM ; ){
		if(refer->jt.slot[i].flag != 0 && refer->jt.slot[j].flag != 0 && i < j){				
			transit = ((refer->jt.slot[j].rx_time - refer->jt.slot[i].rx_time) - ( refer->jt.slot[j].tx_time - refer->jt.slot[i].tx_time) / 8000.0 * 1000.0)/(double)(j-i);
			if(start){
				lastTransit = transit;
				OSAL_trace(eRTPP, eDebug,"i:%d,j:%d,lastTransit:%0.3f,transit:%0.3f,deltaTransit:%0.3f,jitter:%0.3f\n",i,j,lastTransit,transit,deltaTransit,jitter);
				start = 0;
			}else{
				deltaTransit = transit - lastTransit;
				if(deltaTransit < 0.0)
					deltaTransit = -deltaTransit;
				jitter += (deltaTransit - jitter) / 16.0; 
				OSAL_trace(eRTPP, eDebug,"i:%d,j:%d,lastTransit:%0.3f,transit:%0.3f,deltaTransit:%0.3f,jitter:%0.3f\n",i,j,lastTransit,transit,deltaTransit,jitter);
				lastTransit = transit;
			}

			i++;
			j++;
		}

		if(refer->jt.slot[j].flag == 0){
			for( ; j < JT_SLOT_NUM ; j++){
				if(refer->jt.slot[j].flag != 0)
					break;
			}
		}

		if(refer->jt.slot[i].flag == 0){
			for( ; i <= j ; i++){
				if(refer->jt.slot[i].flag != 0)
					break;
			}
		}

		if(i == j)
			j++;
	}
	
    memcpy(reportflagbuf,FLAG_STR_JITTER_REPORT,strlen(FLAG_STR_JITTER_REPORT));
    memset(ipbuf,0,sizeof(ipbuf));
	inet_ntop(AF_INET,&refer->fip,ipbuf,sizeof(ipbuf));	
	OSAL_trace(eRTPP, eInfo, "%s %s:%d to %s:%d %s to %s rtp_stream:%x real_jitter:%.2f",
			reportflagbuf,ipbuf, ntohs(refer->fport), RtppGlobals.localip[refer->p->index], refer->p->port, 
			refer->ss->f_tag,refer->ss->to_tag , refer->packet.ssrc,jitter);

	memset(refer->jt.slot,0x0,JT_SLOT_NUM * sizeof(struct jt_node));

	res = &refer->jt.snap[refer->jt.list_c];
	res->jitter = jitter;
	res->ts = (time(OSAL_NULL))&0x7fffffff;
	refer->jt.list_c++;
	refer->jt.total++;
	if(JT_SNAP_NUM == refer->jt.list_c){
		refer->jt.list_c = 0;
	}
}

void rtpp_jt_end(port_info_t *refer,rtpp_session_t *ss)
{
    OSAL_CHAR strbuf[4*1024 + 1] = {0};
    OSAL_CHAR ipbuf[100] = {0};
    struct tm tts = {0};
    int iStrbuffLen = 0;
	int print = 0;
	int i = 0;

	if(!refer->jt_calc){
		return;
	}

    memset(strbuf, 0, sizeof(strbuf));
    memset(ipbuf,0,sizeof(ipbuf));
    inet_ntop(AF_INET,&refer->fip,ipbuf,sizeof(ipbuf));
	iStrbuffLen = 0;
    iStrbuffLen+=snprintf(strbuf +  iStrbuffLen, 4*1024+1 - iStrbuffLen, "%s %s:%d to %s:%d  %s to %s rtp_stream:%x jitter_count:%d jitters:[", 
	 		FLAG_STR_SNAP_JITTER,ipbuf, ntohs(refer->fport), RtppGlobals.localip[refer->p->index], refer->p->port,  
	 		ss->f_tag,ss->to_tag, refer->realtime_lost.last_calc_ssrc, refer->jt.total);

	print = refer->jt.total>=JT_SNAP_NUM?JT_SNAP_NUM:refer->jt.total;
	for(i = 0;i < print;i++){
		localtime_r(&refer->jt.snap[i].ts, &tts);
		iStrbuffLen += snprintf(strbuf+iStrbuffLen, 4*1024+1 - iStrbuffLen, "%2.2u:%2.2u:%2.2u %.2f  ", tts.tm_hour, tts.tm_min, tts.tm_sec,refer->jt.snap[i].jitter);
		if(iStrbuffLen >= 4000){
			iStrbuffLen = 0;
			OSAL_trace(eRTPP, eSys, "%s", strbuf);
			memset(strbuf, 0, sizeof(strbuf));
		}
	}
		
	iStrbuffLen +=snprintf(strbuf+iStrbuffLen, 4*1024 - iStrbuffLen, "]");
	OSAL_trace(eRTPP, eSys, "%s", strbuf);
}

int rtpp_media_end(rtpp_session_t *ss)
{
	port_info_t *lrefer = NULL;
	port_info_t *rrefer = NULL;
	struct tm tts1 = {0};
	struct tm tts2 = {0};
	struct tm tts3 = {0};
	struct tm tts4 = {0};
	OSAL_UINT16 delay = 1000;
	OSAL_UINT16 m1delay = 1000;
	OSAL_UINT16 m2delay = 1000;
	OSAL_UINT16 lno = 1000;
	OSAL_UINT16 rno = 1000;
	if(!ss) return -1;
	lrefer = &ss->left.audio;
	rrefer = &ss->right.audio;
	time_t tmp;
	OSAL_UINT64 CurrentTime = OSAL_get_msecs();

	if(!lrefer->p||!rrefer->p) {
		OSAL_trace(eRTPP, eError, "%s to %s lrp:%p,rrp:%p",ss->f_tag,ss->to_tag,lrefer->p,rrefer->p);
		return -1;
	}

	if(ss->connect_time){
		delay = ss->connect_time - ss->create_time;
	}
	if(lrefer->media_last_active){
		lno = (CurrentTime-lrefer->media_last_active)/1000;
	}
	if(rrefer->media_last_active){
		rno = (CurrentTime-rrefer->media_last_active)/1000;
	}

	if(lrefer->first_media_time){
		tmp = lrefer->first_media_time/1000;
		m1delay = tmp - ss->create_time;
		localtime_r(&tmp, &tts1);
	}
	
	if(lrefer->media_last_active){
		tmp = lrefer->media_last_active/1000;
		localtime_r(&tmp, &tts2);
	}
	
	if(rrefer->first_media_time){
		tmp = rrefer->first_media_time/1000;
		m2delay = tmp - ss->create_time;
		localtime_r(&tmp, &tts3);
	}
	
	if(rrefer->media_last_active){
		tmp = rrefer->media_last_active/1000;
		localtime_r(&tmp, &tts4);
	}

	/*µ¥Í¨µÄ¶¨Òå½ÓÌýºó¹Ò¶ÏÇ°Ã»ÓÐÊÕµ½Ã½ÌåµÄÊ±¼ä´óÓÚ3S »òÒÔÉÏ*/
	OSAL_trace(eRTPP, eSys, "%s to %s key:%s connect_time:%d m1delay:%d m2delay:%d reason:%d "
		"left_rtp_stream:%x left_first:%2.2u:%2.2u:%2.2u left_last:%2.2u:%2.2u:%2.2u left_no_media:%d "
		"right_rtp_stream:%x right_first:%2.2u:%2.2u:%2.2u right_last:%2.2u:%2.2u:%2.2u right_no_media:%d",
		ss->f_tag,ss->to_tag, ss->call_id,delay,m1delay,m2delay,ss->release_reason,
		lrefer->realtime_lost.last_calc_ssrc,tts1.tm_hour, tts1.tm_min, tts1.tm_sec,tts2.tm_hour, tts2.tm_min, tts2.tm_sec,lno,
		rrefer->realtime_lost.last_calc_ssrc,tts3.tm_hour, tts3.tm_min, tts3.tm_sec,tts4.tm_hour, tts4.tm_min, tts4.tm_sec,rno);
	return 0;
}

void rtp_media_quality_handle(port_info_t *refer,OSAL_INT32 nCalcType)
{
    	realtime_lost_entry *stats_entry = NULL;
	OSAL_UINT32  calc_intval = 3000;/*Ä¬ÈÏ¶ª°ü¼ÆËãÆµÂÊÎª3000ºÁÃë*/
	char *tmp;
	OSAL_UINT16 lost;

	/*Ë½ÓÐÐ­Òé²»Í³¼Æ*/
	if(refer->private_rtp){
		return;
	}
	
	if(nCalcType == RealTime_Lost_Fec){
		stats_entry = &refer->realtime_lost_fec;
		tmp = FLAG_STR_FEC;
	}
	else if(nCalcType == RealTime_Lost){		
		stats_entry = &refer->realtime_lost;
		tmp = FLAG_STR_REALTIME;
	}
	else if(nCalcType == RealTime_Lost_Rtcp){
		stats_entry = &refer->realtime_lost_rtcp;
		tmp = FLAG_STR_RTCP;
		if(!refer->fec_local_smooth_lost)
			calc_intval = 80;
		else
			calc_intval = 500;
	}	
	else{
		OSAL_trace(eRTPP, eError, "Unknow calc type:%d!",nCalcType);
		return;
	}

	if(stats_entry->is_first_packet_received == 0) {
		__init_real_lost_buf(refer,stats_entry);
		stats_entry->is_first_packet_received=1;
		return;
	}

	//RTPµÄ»á»°Ô´·¢Éú±ä»¯ÀÛ¼Ó
	if ( stats_entry->last_calc_ssrc != refer->packet.ssrc){
		/*realtime lost*/
		refer->calu_value = CALC_SSRC;
		lost = __realtime_lost_calc__(refer,nCalcType);
		__init_real_lost_buf(refer,stats_entry);
		if(nCalcType == RealTime_Lost) {
			rtpp_rc_control(refer, lost);
			rtpp_jt_calc(refer);
		}
		return;
	}

	//RTPµÄ°üÐòºÅ³öÏÖ»ØÈÆÇé¿ö
	if ( (stats_entry->current_seq > refer->packet.seq)  && (stats_entry->last_calc_ts < refer->packet.ts)\
			&& (stats_entry->current_seq > 0xff00) && (refer->packet.seq < 0x0ff) ){
		/*realtime lost*/
		refer->calu_value = CALC_LOOP;
		lost = __realtime_lost_calc__(refer,nCalcType);
		__init_real_lost_buf(refer,stats_entry);
		if(nCalcType == RealTime_Lost){
			rtpp_rc_control(refer, lost);
			rtpp_jt_calc(refer);
		}
		return;
	}

	//Í¨³£Çé¿ö
	if (  stats_entry->current_seq <= refer->packet.seq ){
		/*Ç°Ïò¶¶¶¯³¬¹ý100µÄÖØÐÂ¼ÆËã*/
		if(refer->packet.seq - stats_entry->current_seq >=100){
			/*realtime lost*/
			if(nCalcType == RealTime_Lost){
				OSAL_trace(eRTPP, eSys, "ssrc:%x,rtp_seq:%d,cur_seq %d front jitter gt 100",
					refer->packet.ssrc,refer->packet.seq,stats_entry->current_seq);
			}
			refer->calu_value = CALC_FJITERR;
			lost = __realtime_lost_calc__(refer,nCalcType);
			__init_real_lost_buf(refer,stats_entry);
			if(nCalcType == RealTime_Lost){
				rtpp_rc_control(refer, lost);
				rtpp_jt_calc(refer);
			}
			return;
		}
	}else{
		/*ºóÏò¶¶¶¯³¬¹ý100µÄÖØÐÂ¼ÆËã*/
		if( stats_entry->current_seq - refer->packet.seq >=100){
			/*realtime lost*/
			if(nCalcType == RealTime_Lost){
				OSAL_trace(eRTPP, eSys, "ssrc:%x,rtp_seq:%d,cur_seq %d back jitter gt 100",
					refer->packet.ssrc,refer->packet.seq,stats_entry->current_seq);
			}
			refer->calu_value = CALC_BJITERR;
			lost = __realtime_lost_calc__(refer,nCalcType);
			__init_real_lost_buf(refer,stats_entry);
			if(nCalcType == RealTime_Lost){
				rtpp_rc_control(refer, lost);
				rtpp_jt_calc(refer);
			}
			return;
		}
	}
		
	//put in map
	stats_entry->current_seq = (refer->packet.seq - stats_entry->current_seq > 0) ? refer->packet.seq : stats_entry->current_seq;
	int idx = refer->packet.seq - stats_entry->last_calc_seq;
	if (idx > 0 && idx < SEQ_MAP_LEN && stats_entry->seq_map[idx] == OSAL_FALSE)
	{
		stats_entry->rcv_count++;
		stats_entry->seq_map[idx] = OSAL_TRUE;
		OSAL_trace(eRTPP, eInfo, "%s buf add:ssrc:%x,rtp_seq:%d,recv:%d",tmp,refer->packet.ssrc,refer->packet.seq, stats_entry->rcv_count);
	}else
	{
		OSAL_trace(eRTPP, eWarn, "%s buf add:ssrc:%x,rtp_seq:%d,last seq %u,cur seq %u",
			tmp,refer->packet.ssrc,refer->packet.seq, stats_entry->last_calc_seq,stats_entry->current_seq);
	}

	if(nCalcType == RealTime_Lost_Fec && refer->fec_rec){
		if(!refer->packet.rsd_flag)
			rtpp_rc_push(refer,&refer->rcctr->pre,refer->packet.buf,refer->packet.len,refer->packet.seq);

		rtpp_rc_push(refer,&refer->rcctr->after,refer->packet.buf,refer->packet.len,refer->packet.seq);
	}

	if (nCalcType == RealTime_Lost) {
		rtpp_jt_push_slot(refer,refer->packet.buf);
	}

	/*ÈßÓà°ü²»×÷³¬Ê±½áËã*/
	if(refer->packet.rsd_flag){
		return;
	}
	
	//calc realtime lostrate
	if ((refer->packet.recv_time - stats_entry->last_calc_systs)  >= calc_intval){
		refer->calu_value = CALC_TIME;
		lost = __realtime_lost_calc__(refer,nCalcType);
		__init_real_lost_buf(refer,stats_entry);
		if(nCalcType == RealTime_Lost){
			rtpp_rc_control(refer, lost);
			rtpp_jt_calc(refer);
		}
	}
}

void rtpp_get_statistics(rtpp_session_t *ss, double *left_loss, double *right_loss, int *left_pt, int *right_pt)
{
    realtime_lost_entry  *real_lost;
    OSAL_CHAR strbuf[4*1024 + 1] = {0};
    OSAL_CHAR ipbuf[100] = {0};
    struct tm tts = {0};
    int i, slot_num,iStrbuffLen;
	if ( !ss || !left_loss || !right_loss || !left_pt || !right_loss )
	{
        OSAL_trace(eRTPP, eError, "invalid params");
		return;
	}

    *left_pt = ss->left.audio[0].packet.pt;
    *right_pt = ss->right.audio[0].packet.pt;

	if (!ss->left.audio[0].p || !ss->right.audio[0].p ){
		OSAL_trace(eRTPP, eError, "caller:%s,callee:%s,key:%s [%s] no alloc",ss->f_tag,ss->to_tag,
		ss->call_id,porttype2str(ss->left.audio[0].va_flag));
		return;
	}
	  
     /*realtime lost*/
     real_lost =   &ss->left.audio[0].realtime_lost;
     memset(strbuf, 0, sizeof(strbuf));
     memset(ipbuf,0,sizeof(ipbuf));
     inet_ntop(AF_INET,&ss->left.audio[0].fip,ipbuf,sizeof(ipbuf));
     iStrbuffLen = 0;
     iStrbuffLen+=snprintf(strbuf +  iStrbuffLen, 4*1024 - iStrbuffLen, "%s %s:%d -> %s:%d  %s -> %s rtp_stream:%x segment_count:%d lost_count:%d losts:[", 
	 		FLAG_STR_SNAP_REPORT,ipbuf, ntohs(ss->left.audio[0].fport), RtppGlobals.localip[ss->left.audio[0].p->index], ss->left.audio[0].p->port,  
	 		ss->f_tag,ss->to_tag, real_lost->last_calc_ssrc, real_lost->calc_count, real_lost->rt_index);
     slot_num = (real_lost->rt_index > REALLOST_SLOT_NUM) ? REALLOST_SLOT_NUM : real_lost->rt_index;
     for (i = 0; i < slot_num; i++) {
        memset(&tts,0,sizeof(struct tm ));
		localtime_r(&(real_lost->rt_lostrate[i].ts), &tts);
	 	iStrbuffLen += snprintf(strbuf+iStrbuffLen, 4*1024 - iStrbuffLen, "%2.2u:%2.2u:%2.2u %.4f  ", tts.tm_hour, tts.tm_min, tts.tm_sec, real_lost->rt_lostrate[i].lost / 10000.0);
	 }
    iStrbuffLen +=snprintf(strbuf+iStrbuffLen, 4*1024 - iStrbuffLen, "]");
	if(real_lost->calc_count>0) *left_loss = real_lost->total_lost/(real_lost->calc_count*10000.0);
	iStrbuffLen +=snprintf(strbuf+iStrbuffLen, 4*1024 - iStrbuffLen, " laverage_lost:%.4f",*left_loss);
    OSAL_trace(eRTPP, eSys, "%s", strbuf);

     real_lost =   &ss->right.audio[0].realtime_lost;
     memset(strbuf, 0, sizeof(strbuf));
     memset(ipbuf,0,sizeof(ipbuf));
     inet_ntop(AF_INET,&ss->right.audio[0].fip,ipbuf,sizeof(ipbuf));
     iStrbuffLen = 0;
     iStrbuffLen += snprintf(strbuf +  iStrbuffLen, 4*1024 - iStrbuffLen, "%s %s:%d -> %s:%d  %s -> %s rtp_stream:%x segment_count:%d lost_count:%d losts:[", 
                    FLAG_STR_SNAP_REPORT, ipbuf, ntohs(ss->right.audio[0].fport), RtppGlobals.localip[ss->right.audio[0].p->index], ss->right.audio[0].p->port, 
                     ss->f_tag,ss->to_tag, real_lost->last_calc_ssrc, real_lost->calc_count, real_lost->rt_index);
     slot_num = (real_lost->rt_index > REALLOST_SLOT_NUM) ? REALLOST_SLOT_NUM : real_lost->rt_index;
     for (i = 0; i < slot_num; i++) {
     	memset(&tts,0,sizeof(struct tm ));
	 	localtime_r(&(real_lost->rt_lostrate[i].ts), &tts);
	 	iStrbuffLen+=snprintf(strbuf +  iStrbuffLen, 4*1024 - iStrbuffLen, "%2.2u:%2.2u:%2.2u %.4f  ",  tts.tm_hour, tts.tm_min, tts.tm_sec, real_lost->rt_lostrate[i].lost / 10000.0);
     }
    iStrbuffLen += snprintf(strbuf+iStrbuffLen, 4*1024 - iStrbuffLen, "]");
	if(real_lost->calc_count>0) *right_loss = real_lost->total_lost/(real_lost->calc_count*10000.0);
	iStrbuffLen +=snprintf(strbuf+iStrbuffLen, 4*1024 - iStrbuffLen, " raverage_lost:%.4f",*right_loss);
	OSAL_trace(eRTPP, eSys, "%s", strbuf);

}

OSAL_INT32 rtpp_recv_rtcp_fec(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{
	OSAL_CHAR *p;
	rtcphdr_t  *rtcphdr;
	OSAL_UINT32 lost = 0;
	OSAL_UINT32 ssrc = 0;
	struct in_addr addr;
	OSAL_CHAR addr_str[16];

	if(!refer)
		return -1;
	
	p = buf;
	rtcphdr = (rtcphdr_t *)p;

	if(rtcphdr->pt == RTCP_PT_FEC)
	{
		p += sizeof(rtcphdr_t);
		ssrc = ntohl(*(OSAL_UINT32*)(p-4));
		lost = ntohl(*(OSAL_UINT32*)p);
		refer->fec_peer_lost = lost;

		addr.s_addr = refer->fip;
		inet_ntop(AF_INET,&addr,addr_str,sizeof(addr_str));
		
		OSAL_trace(eRTPP, eInfo, "recv fec rtcp from %s:%u,ssrc:%x lost:%.4f succeed!!",
			addr_str,ntohs(refer->frtcpport),ssrc,lost/10000.0);

		rtpp_send_rtcp_fec_rsp(refer,ssrc);

		return 1;
	}
	else if(rtcphdr->pt == RTCP_PT_FEC_RSP)
	{
		/*½ÓÊÕ³É¹¦ºó*/
		refer->fec_ack_ts = OSAL_get_msecs();
		addr.s_addr = refer->fip;
		inet_ntop(AF_INET,&addr,addr_str,sizeof(addr_str));
		OSAL_trace(eRTPP, eInfo, "recv fec rtcp rsp from %s:%u,ssrc:%x rtt:%u ms!!",
			addr_str,ntohs(refer->frtcpport),refer->realtime_lost_rtcp.last_calc_ssrc,refer->fec_ack_ts-refer->fec_syn_ts);
		refer->fec_syn_ts = 0;
		return 1;
	}
	else
	{
		return 0;
	}
}

OSAL_INT32 rtpp_send_rtcp_fec_rsp(port_info_t *refer,OSAL_UINT32 ssrc)
{
	OSAL_CHAR send_buf[1024] = {0};
	OSAL_INT32 send_len = 0;
	rtcphdr_t  *rtcphdr;
	struct sockaddr_in to_ip;
	struct in_addr addr;
	OSAL_CHAR addr_str[16];

	memset(&addr,0,sizeof(addr));
	memset(addr_str,0,sizeof(addr_str));
	
	if (!refer || !refer->p)
		return -1;
	
	rtcphdr = (rtcphdr_t*)send_buf;

	rtcphdr->ver = 02;
	rtcphdr->padding = 0;
	rtcphdr->rc = 0;
	rtcphdr->pt = RTCP_PT_FEC_RSP;
	rtcphdr->ssrc = htons(ssrc);
	rtcphdr->length = 0;
	send_len = sizeof(rtcphdr_t);
	
	to_ip.sin_family = AF_INET;
	to_ip.sin_port	= refer->frtcpport;
	to_ip.sin_addr.s_addr = refer->fip;
	if (sendto(refer->p->rtcpfd, send_buf, send_len, 0, (struct sockaddr*)&to_ip, sizeof(to_ip)) < 0) {
		OSAL_trace(eRTPP, eWarn, "send FEC rtcp ack packet faile!");
		return -1;
	}
	
	addr.s_addr = refer->fip;
	inet_ntop(AF_INET,&addr,addr_str,sizeof(addr_str));
	
	OSAL_trace(eRTPP, eInfo, "send fec rtcp ack to %s:%u,ssrc:%x succeed!!",
		addr_str,ntohs(refer->frtcpport),ssrc);
	return 0;
}


OSAL_INT32 rtpp_send_rtcp_fec(port_info_t *refer)
{
	OSAL_CHAR send_buf[1024] = {0};
	OSAL_INT32 send_len = 0;
	rtcphdr_t  *rtcphdr;
	OSAL_UINT32 *lost;
	struct sockaddr_in to_ip;
	struct in_addr addr;
	OSAL_CHAR addr_str[16];

	memset(&addr,0,sizeof(addr));
	memset(addr_str,0,sizeof(addr_str));
	
	if (!refer || !refer->p)
		return -1;
	
	rtcphdr = (rtcphdr_t*)send_buf;

	rtcphdr->ver = 02;
	rtcphdr->padding = 0;
	rtcphdr->rc = 0;
	rtcphdr->pt = RTCP_PT_FEC;
	rtcphdr->ssrc = htonl(refer->realtime_lost_rtcp.last_calc_ssrc);
	rtcphdr->length = 3;
	send_len = sizeof(rtcphdr_t);

	lost = (OSAL_UINT32*)(rtcphdr + 1);
	*lost = htonl(refer->fec_local_smooth_lost);
	send_len += 4;
	
	to_ip.sin_family = AF_INET;
	to_ip.sin_port	= refer->frtcpport;
	to_ip.sin_addr.s_addr = refer->fip;
	if (sendto(refer->p->rtcpfd, send_buf, send_len, 0, (struct sockaddr*)&to_ip, sizeof(to_ip)) < 0) {
		OSAL_trace(eRTPP, eWarn, "send FEC rtcp packet faile!");
		return -1;
	}

	/*·¢ËÍ³É¹¦ºóµÈ´ýACKÈ·ÈÏ*/
	refer->fec_syn_ts = OSAL_get_msecs();
	refer->fec_ack_ts = 0;
	
	addr.s_addr = refer->fip;
	inet_ntop(AF_INET,&addr,addr_str,sizeof(addr_str));
	
	OSAL_trace(eRTPP, eInfo, "send fec rtcp to %s:%u,ssrc:%x lost:%.4f smooth lost:%.4f succeed!!",
		addr_str,ntohs(refer->frtcpport),refer->realtime_lost_rtcp.last_calc_ssrc,refer->fec_local_lost/10000.0,refer->fec_local_smooth_lost/10000.0);
	return 0;
}


OSAL_INT32 rtpp_resend_rtcp_fec(port_info_t *refer)
{
	OSAL_CHAR send_buf[1024] = {0};
	OSAL_INT32 send_len = 0;
	rtcphdr_t  *rtcphdr;
	OSAL_UINT32 *lost;
	struct sockaddr_in to_ip;
	struct in_addr addr;
	OSAL_CHAR addr_str[16];

	memset(&addr,0,sizeof(addr));
	memset(addr_str,0,sizeof(addr_str));
	
	if (!refer || !refer->p)
		return -1;
	
	rtcphdr = (rtcphdr_t*)send_buf;

	rtcphdr->ver = 02;
	rtcphdr->padding = 0;
	rtcphdr->rc = 0;
	rtcphdr->pt = RTCP_PT_FEC;
	rtcphdr->ssrc = htonl(refer->realtime_lost_rtcp.last_calc_ssrc);
	rtcphdr->length = 3;
	send_len = sizeof(rtcphdr_t);

	lost = (OSAL_UINT32*)(rtcphdr + 1);
	*lost = htonl(refer->fec_local_smooth_lost);
	send_len += 4;
	
	to_ip.sin_family = AF_INET;
	to_ip.sin_port	= refer->frtcpport;
	to_ip.sin_addr.s_addr = refer->fip;
	if (sendto(refer->p->rtcpfd, send_buf, send_len, 0, (struct sockaddr*)&to_ip, sizeof(to_ip)) < 0) {
		OSAL_trace(eRTPP, eWarn, "resend FEC rtcp packet faile!");
		return -1;
	}
	
	addr.s_addr = refer->fip;
	inet_ntop(AF_INET,&addr,addr_str,sizeof(addr_str));
	
	OSAL_trace(eRTPP, eSys, "resend fec rtcp to %s:%u,ssrc:%x lost:%.4f smooth lost:%.4f succeed!!",
		addr_str,ntohs(refer->frtcpport),refer->realtime_lost_rtcp.last_calc_ssrc,refer->fec_local_lost/10000.0,refer->fec_local_smooth_lost/10000.0);
	return 0;
}

OSAL_BOOL inline rtp_calc_discardRtp(port_info_t *refer)
{
	if(refer->discardRtpInteval == 0)
		return TRUE;
	

	if(refer->discardRtpInteval == -1)
	{
		OSAL_trace (eRTPP, eInfo, "discard rtp Inteval:-1, discard this package");
		return FALSE;
	}
	else if(refer->discardRtpInteval == -2)
	{
		OSAL_INT32 iRandom = get_rand_num();
		OSAL_INT32 iDiscard = iRandom % 100;
		if(iDiscard >= 0 && iDiscard < refer->discardNumber)
		{
			OSAL_trace (eRTPP, eInfo, "random discard this rtp :randomNum:%d,LostRate:%d",iDiscard,refer->discardNumber);
			return FALSE;
		}
	}
	else
	{
		if(!refer->Rtpindex){
			do{refer->current_discardRtpInteval = get_rand_num() % refer->discardRtpInteval;}while(!refer->current_discardRtpInteval);
			do{refer->current_discardNumber = get_rand_num() % refer->discardNumber;}while(!refer->current_discardNumber);
			OSAL_trace (eRTPP, eInfo, "ssrc[%x] seq[%d] init random value current[%d:%d] max[%d:%d]",refer->packet.ssrc,refer->packet.seq,
				refer->current_discardRtpInteval,refer->current_discardNumber,
				refer->discardRtpInteval,refer->discardNumber);
		}
		if(refer->Rtpindex == refer->current_discardRtpInteval+refer->current_discardNumber-1){
			OSAL_trace (eRTPP, eInfo, "ssrc[%x] random discard rtp seq[%d] finsh!",refer->packet.ssrc,refer->packet.seq);
			refer->Rtpindex = 0;
			return FALSE;
		}else if(refer->Rtpindex>=refer->current_discardRtpInteval){
			OSAL_trace (eRTPP, eInfo, "ssrc[%x] random discard rtp seq[%d]!",refer->packet.ssrc,refer->packet.seq);
			refer->Rtpindex++;
			return FALSE;
		} 
		refer->Rtpindex++;
	}
	return TRUE;
}

OSAL_INT32 work_rtcp_handle(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{
	if (!refer || !refer->trans || !refer->trans->p) {
		OSAL_trace (eRTPP, eExcept, "refer or refer->trans  or refer->trans->p  is null");
		return OSAL_ERROR;
	}

	if(refer->fec_mode == FEC_DECODE_PKT) {
		if (1 == rtpp_recv_rtcp_fec(refer, buf, len)) // eat it
			return OSAL_OK;
	}

	if(refer->trans->frtcpport == 0) {
		OSAL_trace (eRTPP, eInfo, "rtcp dst port null");
		return OSAL_OK;
	}

	rtpp_udp_trans(refer->trans->p->rtcpfd,buf,len,refer->trans->fip,refer->trans->frtcpport);	
	refer->trans->send_packets++;
	refer->trans->send_bytes += len;

	return OSAL_OK;
}

OSAL_INT32 work_record_proc(port_info_t *refer, OSAL_UINT8 *buf, OSAL_INT32 len)
{
	if(refer->rrcs) rwrite(refer->rrcs, buf, len);
	else OSAL_trace(eRTPP, eError, "caller:%s,callee:%s,key:%s %s record handle null? fixed",
		refer->ss->f_tag,refer->ss->to_tag,refer->ss->call_id,porttype2str(refer->va_flag));
	return 0;
}

OSAL_INT32 work_fec_date_proc(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{
	fec_media_data_t	indata;
	fec_media_data_t	outdata[5];
	unsigned char		buffer[5][1500];
	OSAL_INT32  rtp_number = 0;
	OSAL_INT32 i = 0;
	st_PRTPP_chan chanel = {0};

	memset(buffer,0,sizeof(buffer));

	indata.data = (unsigned char *)buf;
	indata.slen= len;
	outdata[0].data = buffer[0];
	outdata[1].data = buffer[1];
	outdata[2].data = buffer[2];
	outdata[3].data = buffer[3];
	outdata[4].data = buffer[4];

	OSAL_trace(eRTPP, eDebug, "%s packet, indata len is %d,peer lost:%d",  refer->fec_mode ? "encode" : "decode", indata.slen,refer->trans->fec_peer_lost);
	/*Â¼ÒôÔÚ±àÂë²à*/		
	if(refer->ss->record_flag && refer->fec_mode){
		work_record_proc(refer,buf,len);
	}
	
	if(fec_process(refer->ss->fec_inst, refer->fec_mode, &indata, outdata, &rtp_number, refer->trans->fec_peer_lost) == -1){
		OSAL_trace(eRTPP, eError, "fec process error");
		return -1;
	}
	for(i = 0; i < rtp_number;i++){
		/*Â¼ÒôÔÚ½âÂë²à*/
		OSAL_trace(eRTPP, eDebug, "%s fec packet, outdata len is %d,rsd num:%d",  refer->fec_mode ? "encode" : "decode", outdata[i].slen,rtp_number);
		if(!refer->fec_mode){
			if(refer->ss->record_flag)
				work_record_proc(refer,outdata[i].data,outdata[i].slen);
			if(outdata[i].slen>=12){
				RTP_HDR *rh = (RTP_HDR *)outdata[i].data;
				refer->packet.pt = rh->PT;
				refer->packet.seq= ntohs(rh->sn);
				refer->packet.ssrc = ntohl(rh->SSRC);	
				refer->packet.ts= ntohl(rh->ts);
				refer->packet.buf = outdata[i].data;
				refer->packet.len = outdata[i].slen;
				refer->packet.rsd_flag = 0;
				if(i != rtp_number - 1)
					refer->packet.rsd_flag = 1;
				rtp_media_quality_handle(refer, RealTime_Lost_Fec);
			}
		}
		
		if(refer->trans->private_rtp){
			RTPToPRTP(&chanel,outdata[i].data,&outdata[i].slen);
		}
				
		rtpp_udp_trans(refer->trans->p->fd,(char *)outdata[i].data,outdata[i].slen,refer->trans->fip,refer->trans->fport);
		refer->trans->send_packets++;
		refer->trans->send_bytes += outdata[i].slen;
		
	}
	return 0;
}
OSAL_INT32 work_standard_rtp_proc(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{
	/*fecÓÅÏÈ¼¶×î¸ß*/
	if(refer->ss->fec_flag){
		work_fec_date_proc(refer,buf,len);
		return 0;
	}

	if(refer->ss->record_flag){
		work_record_proc(refer,buf,len);
	}
	
	if(refer->trans->private_rtp){
		RTPToPRTP(&refer->s2pchan,buf,&len);
	}
	
	rtpp_udp_trans(refer->trans->p->fd,buf,len,refer->trans->fip,refer->trans->fport);
	refer->trans->send_packets++;
	refer->trans->send_bytes += len;
	
	return 0;
}

OSAL_INT32 work_private_rtp_proc(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{	
	/*Ë½ÓÐÖ»´¦ÀíÕâÒ»ÖÖÇé¿ö*/
	if(!refer->trans->private_rtp){
		do {PRTPToRTP(&refer->p2schan, buf, &len);
			/*±ê×¼RTPP ´¦Àí*/
			if(refer->ss->fec_flag){
				work_fec_date_proc(refer,buf,len);
			}else{
				if(refer->ss->record_flag){
					work_record_proc(refer,buf,len);
				}
				if(refer->trans->fport){
					rtpp_udp_trans(refer->trans->p->fd,buf,len,refer->trans->fip,refer->trans->fport);
					refer->trans->send_packets++;
					refer->trans->send_bytes += len;
				}else{
					OSAL_trace(eRTPP, eInfo, "caller:%s,callee:%s,key:%s %s remote port is null",
						refer->ss->f_tag,refer->ss->to_tag,refer->ss->call_id,porttype2str(refer->va_flag));
				}
			}
		}while(refer->p2schan.needParser);
	}else{
		rtpp_udp_trans(refer->trans->p->fd,buf,len,refer->trans->fip,refer->trans->fport);
		refer->trans->send_packets++;
		refer->trans->send_bytes += len;
	}
	
	return 0;
}

OSAL_INT32 work_audio_chanel_proc(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{ 	
	if (refer->private_rtp == 1) 			
		work_private_rtp_proc(refer, buf, len);
	else
		work_standard_rtp_proc(refer, buf, len);

	return 0;
}

/*ÊÓÆµÃ»ÓÐË½ÓÐÍ·ÓëFEC´¦ÀíÂ¼Òô´¦Àí¹ý³Ì*/
OSAL_INT32 work_video_chanel_proc(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{
	if(refer->trans->fport){
		rtpp_udp_trans(refer->trans->p->fd,buf,len,refer->trans->fip,refer->trans->fport);
		refer->trans->send_packets++;
		refer->trans->send_bytes += len;
	}
	return 0;
}

static OSAL_INT32 __fec_rtcp_proc(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{
#define FEC_RTCP_RESND_INTERVAL (200)
#define FEC_RTCP_SND_INTERVAL (500)

	/*¼´Ê¹×ãÁ½¸öÌõ¼þÖ»·¢ËÍÒ»¸ö*/
	if(refer->ss->fec_flag && refer->fec_mode  == FEC_DECODE_PKT){
		if(refer->recv_lost_calc_finish){
			if(__lost2level(refer->fec_local_smooth_lost)!=__lost2level(refer->fec_local_last_smooth_lost)){
				rtpp_send_rtcp_fec(refer);
				refer->fec_rtcp_snd = 1;
			}else{
				refer->fec_rtcp_snd = 0;
			}
			refer->fec_rtcp_resnd = 0;
			refer->fec_ack_ts = 0;
			refer->fec_syn_ts = refer->packet.recv_time;
			refer->recv_lost_calc_finish = 0;
		}else if(refer->fec_rtcp_snd && !refer->fec_ack_ts && !refer->fec_rtcp_resnd 
				&& refer->packet.recv_time - refer->fec_syn_ts >= FEC_RTCP_RESND_INTERVAL){
			rtpp_resend_rtcp_fec(refer); 
			refer->fec_rtcp_resnd = 1;
		}
	}
	return 0;
}

static OSAL_INT32 __first_packet_init(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{
	refer->private_rtp = refer->packet.ver == RTP_VERSION_3;
	if(refer->private_rtp && refer->trans->is_first_packet_received && !refer->trans->private_rtp){
		refer->p2schan.uiSSRC = get_rand_num();
		refer->p2schan.uiSSRC = (refer->p2schan.uiSSRC& 0x0000FFFF) | 0xABCD0000;
	}
	//init real lost
	//__init_real_lost_buf(refer,&refer->realtime_lost);
	/**/
	//__init_real_lost_buf(refer,&refer->realtime_lost_fec);
	//__init_real_lost_buf(refer,&refer->realtime_lost_rtcp);
	return 0;
}

static OSAL_INT32 __parse_rtp_packet(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{
	refer->packet.ver = buf[0]&0xC0;

	/*packet check*/
	if(refer->packet.ver == RTP_VERSION_2 ){
		if(len < 12){
			OSAL_trace(eRTPP, eError, "caller:%s,callee:%s,key:%s [%s] port %d recv std rtp packet less len:%d",refer->ss->f_tag,refer->ss->to_tag,
				refer->ss->call_id,porttype2str(refer->va_flag),refer->p->port,len);
			return -1;
		}
		RTP_HDR *rh = (RTP_HDR *)buf;
		refer->packet.pt = rh->PT;
		refer->packet.seq= ntohs(rh->sn);
		refer->packet.ssrc = ntohl(rh->SSRC);	
		refer->packet.ts= ntohl(rh->ts);
	}else if(refer->packet.ver == RTP_VERSION_3){
		if(len < 4){
			OSAL_trace(eRTPP, eError, "caller:%s,callee:%s,key:%s [%s] port %d recv pri rtp packet less len:%d",refer->ss->f_tag,refer->ss->to_tag,
				refer->ss->call_id,porttype2str(refer->va_flag),refer->p->port,len);
			return -1;
		}
	}else{
		OSAL_trace(eRTPP, eError, "caller:%s,callee:%s,key:%s [%s] port %d recv unknown version %d",refer->ss->f_tag,refer->ss->to_tag,
			refer->ss->call_id,porttype2str(refer->va_flag),refer->p->port,refer->packet.ver);
		return -1;
	}
	
	return 0;
}

/*sdkµÄÐø»îÍ¨µÀ
"RTPP PING REQ";
"RTPP PING RSP";
*/
OSAL_INT32 work_chanel_keep_packet_handle(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{
	if(buf[0] == 'R' && len == 13){
		refer->media_last_active = OSAL_get_msecs();
		OSAL_trace(eRTPP, eInfo, "caller:%s,callee:%s,key:%s %s recv chanel keep packet...",
			refer->ss->f_tag,refer->ss->to_tag,refer->ss->call_id,porttype2str(refer->va_flag));
		if(refer->trans->fport){
			rtpp_udp_trans(refer->trans->p->fd,buf,len,refer->trans->fip,refer->trans->fport);
		}
		return 1;
	}
	return 0;
}

OSAL_INT32 work_rtp_handle(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len)
{	
	if (!refer || !refer->trans || !refer->trans->p) {
		OSAL_trace (eRTPP, eExcept, "refer or refer->trans  or refer->trans->p  is null");
		return OSAL_ERROR;
	}

	if(work_chanel_keep_packet_handle(refer, buf, len)) return 0;
	
	/*pre proc*/
	if(__parse_rtp_packet(refer, buf, len)<0) return -1;

	/*ÉèÖÃ¶ª°üËã·¨Òì³£°ü²»Ëã*/
	if(!rtp_calc_discardRtp(refer))
		return 0;

	refer->recv_packets++;
	refer->recv_bytes += len;
	
	refer->packet.recv_utime = OSAL_get_usecs();
	refer->packet.recv_time = refer->packet.recv_utime/1000;
	refer->packet.rsd_flag = 0;
	refer->packet.buf = buf;
	refer->packet.len = len;
	
	if(refer->is_first_packet_received == 0) {
		__first_packet_init(refer, buf, len);
		rtpp_rc_init(refer);
		refer->first_media_time = refer->packet.recv_time;
		refer->is_first_packet_received=1;
	}

	rtpp_ssrc_statics(refer);
	rtp_media_quality_handle(refer, RealTime_Lost);
	rtp_media_quality_handle(refer, RealTime_Lost_Rtcp);
	__fec_rtcp_proc(refer, buf, len);
	
	refer->media_last_active = refer->packet.recv_time;

	if(!refer->trans->fport){
		OSAL_trace(eRTPP, eInfo, "caller:%s,callee:%s,key:%s %s remote port is null,nothing to do",
			refer->ss->f_tag,refer->ss->to_tag,refer->ss->call_id,porttype2str(refer->trans->va_flag));
		return 0;
	}
	/*proc*/
	if(is_audio(refer->va_flag)){
		work_audio_chanel_proc(refer,buf, len);
	}else if(is_video(refer->va_flag)){
		work_video_chanel_proc(refer,buf, len);
	}else{
		OSAL_trace (eRTPP, eError, "inner port type err %d",refer->va_flag);
	}
	/*end proc*/
	return OSAL_OK;
	
}

OSAL_INT32 work_rtp_rx (OSAL_msgHdr *pMsg)
{
	OSAL_INT32 fd = pMsg->msgSubId;
	OSAL_CHAR buf[RTP_PACKET_MAX_LEN];
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	port_info_t *refer = (port_info_t *)pMsg->param2;
	OSAL_INT32 len;
	OSAL_INT32 ndrain;

	if(refer->p == OSAL_NULL || refer->ss == OSAL_NULL){
		OSAL_trace (eRTPP, eExcept, "inner error refer->p:%p,refer->ss:%p",refer->p,refer->ss);
		return -1;
	}
	
	/* Repeat since we may have several packets queued on the same socket */
	for (ndrain = 0; ndrain < 5; ndrain++) 
	{
		if((len = recvfrom(fd,buf,RTP_PACKET_MAX_LEN-1,0,(struct sockaddr *)&addr,&addrlen)) < 0){
 			return -1;
		}

		RtppGlobals.stats_.rxCounts++;
		RtppGlobals.stats_.rxBytes += len;
		 		
		/////OSAL_trace (eRTPP, eInfo, "recv packet from ip:%s port:%d",inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));
		//OSAL_trace (eRTPP, eDebug, "addr is %s:%d, refer is %s:%d", inet_ntoa(*(struct in_addr*)&addr.sin_addr.s_addr), ntohs(addr.sin_port),
			//inet_ntoa(*(struct in_addr*)&refer->fip), ntohs(refer->fport));

		if(fd == refer->p->rtcpfd){//audio or video rtcp
			OSAL_trace (eRTPP, eInfo, "recv rtcp packet");
			if (!refer->asym) {
				refer->fip = addr.sin_addr.s_addr;
				refer->frtcpport = addr.sin_port;
			}else if(refer->fip != addr.sin_addr.s_addr||refer->frtcpport != addr.sin_port){
				OSAL_CHAR ipbuf1[20] = {0};
				inet_ntop(AF_INET,&refer->fip,ipbuf1,20);
				OSAL_CHAR ipbuf2[20] = {0};
				inet_ntop(AF_INET,&addr.sin_addr.s_addr,ipbuf2,20);
				OSAL_trace(eRTPP, eSys, "%s:%d -> %s:%d %s -> %s key:%s port_type:%s rtp_stream:%x rtcp attack from:%s:%d",
				ipbuf1, ntohs(refer->frtcpport), RtppGlobals.localip[refer->p->index], refer->p->port+1, 
				refer->ss->f_tag,refer->ss->to_tag,refer->ss->call_id,porttype2str(refer->va_flag),
				refer->realtime_lost.last_calc_ssrc,ipbuf2,ntohs(addr.sin_port));
				return 0;
			}
			work_rtcp_handle(refer, buf, len);
		}else {
			if (!refer->asym) {
				refer->fip = addr.sin_addr.s_addr;
				refer->fport = addr.sin_port;
			}else if(refer->fip != addr.sin_addr.s_addr||refer->fport!= addr.sin_port){
				OSAL_CHAR ipbuf3[20] = {0};
				inet_ntop(AF_INET,&refer->fip,ipbuf3,20);
				OSAL_CHAR ipbuf4[20] = {0};
				inet_ntop(AF_INET,&addr.sin_addr.s_addr,ipbuf4,20);
				OSAL_trace(eRTPP, eSys, "%s:%d -> %s:%d %s -> %s key:%s port_type:%s rtp_stream:%x rtp attack from:%s:%d",
				ipbuf3, ntohs(refer->fport), RtppGlobals.localip[refer->p->index], refer->p->port, 
				refer->ss->f_tag,refer->ss->to_tag,refer->ss->call_id,porttype2str(refer->va_flag),
				refer->realtime_lost.last_calc_ssrc,ipbuf4,ntohs(addr.sin_port));
				return 0;
			}
			work_rtp_handle(refer, buf, len);
		}

	}
	
	return OSAL_OK;
}

OSAL_INT32 rtpp_restart_media_time (rtpp_session_t *ss)
{
	OSAL_timerMsgHdrT t;

	memset(&t,0,sizeof(t));

	if(ss->mtime)  OSAL_stimerStop(ss->mtime);

	t.moduleId = ss->mod_id;
	t.param1 = RTPP_TIME_MEDIA;
	t.param2 = (OSAL_UINTPtr)ss;
	ss->mtime = OSAL_stimerStart(&t,MEDIA_CHECK_TIME_LEN*1000);
	return 0;
}

OSAL_INT32 rtpp_start_media_time (rtpp_session_t *ss)
{
	OSAL_timerMsgHdrT t;

	memset(&t,0,sizeof(t));

	t.moduleId = ss->mod_id;
	t.param1 = RTPP_TIME_MEDIA;
	t.param2 = (OSAL_UINTPtr)ss;
	ss->mtime = OSAL_stimerStart(&t,MEDIA_CHECK_TIME_LEN*1000);
	return 0;
}

OSAL_INT32 rtpp_update_callee_mediaIP(OSAL_CHAR *calleeMediaIp,OSAL_CHAR *calleeMediaPort,rtpp_session_t *ss)
{
	OSAL_INT32 intip  = 0;
	OSAL_UINT16 port  = 0;

	if(calleeMediaIp == NULL || calleeMediaPort == NULL)
	{
		OSAL_trace(eRTPP, eError,"media from ip %s calleeMediaPort %s is invalid", calleeMediaIp,calleeMediaPort);
		return -1;
	}
	
	if(inet_pton(AF_INET,calleeMediaIp,&intip) != 1){
		OSAL_trace(eRTPP, eError,"media from ip %s is invalid", calleeMediaIp);
		return -1;
	}


	port = atoi(calleeMediaPort);

	rtpp_update_right_aport(intip,0, port,ss->right.audio[0].asym,ss);
	return 0;
}


OSAL_INT32 rtpp_u_proc (OSAL_msgHdr *pMsg)
{
	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_INT32 argc;
	OSAL_INT32 intip = 0;
	OSAL_INT32 audioport = 0,vedioport = 0;
	OSAL_INT32 i = 0,res = 0;
	OSAL_CHAR callid[RTPP_MAX_CALLID_LEN];
	rtpp_session_t *ss;
	OSAL_CHAR *cookie,*op,*ip,*port, *fromtag,*totag,*notify;
	OSAL_CHAR *tmp;
	OSAL_INT32 recover = 0;                     //o2???¡À?¨°
	OSAL_INT32 link_flags = 0;
	OSAL_CHAR link_ip[RTPP_MAX_IP_LEN] = {0};
	OSAL_INT32 complete_flags = 0;
	OSAL_INT32 asym_flags = 0;
	OSAL_INT32 video_flag = 0;
	OSAL_INT32 tsc_flag = 0;
	OSAL_INT32 fec_flag = 0;
	OSAL_INT32 fec_mode = -1;
	OSAL_INT32 record_flag = 0;
	OSAL_INT32 branche = -1;
	OSAL_INT32 port_index = 0;
	OSAL_CHAR *name;
	OSAL_CHAR record_callid[RTPP_MAX_RECORD_CALLID];
	OSAL_INT32 length;
	mixer_participant_t mp;
	OSAL_INT32 pt[2] = {106, 18};		
	OSAL_INT32 mod_id = pMsg->msgSubId;
	OSAL_INT32 fip = pMsg->param;
	OSAL_UINT16 fport = pMsg->param2;
	OSAL_CHAR *msg = (OSAL_CHAR  *)pMsg->pContent;
	OSAL_INT32 len = pMsg->contentLen;


	command_parse(msg,len,argv,&argc);

	//parm check
	if(7 != argc){
		OSAL_trace (eRTPP, eError, "msg argc err %d %s",argc,msg);
		return -1;
	}
	
	/*cookie	 op 	ip port 	from 	to 	notify 	content*/
	cookie = argv[0];
	op = argv[1];
	ip = argv[2];
	port = argv[3];
	fromtag = argv[4];
	totag = argv[5];
	notify = argv[6];
	
	if(get_callid(cookie,callid) < 0){
		OSAL_trace (eRTPP, eError, "callid failed %s",msg);
		return -1;
	}
	
	//op proc
	for(tmp = op +1; *tmp; tmp++){
		switch (*tmp |= 32){
			case 'a':
				asym_flags= 1;
				break;
			case 'f': 
				complete_flags = 1;
				break;
			case 'l': //bind ip
				tmp = get_link_addr(tmp+1,link_ip);
				link_flags = 1;
				break;
			case 'm':
				OSAL_trace(eRTPP, eDebug, "video flag");
				video_flag = 1;
				break;	
			case 't': // transcoding
				OSAL_trace(eRTPP, eDebug, "transcoding flag");
				tsc_flag = 1;
				break;
			case 'x': // fec flag
				OSAL_trace(eRTPP, eDebug, "fec flag");
				fec_flag = 1;
				fec_mode = atoi(tmp+1);
				if (fec_mode != FEC_DECODE_PKT  &&  fec_mode != FEC_ENCODE_PKT) {
					OSAL_trace(eRTPP, eWarn, "unkown fec mode %d", fec_mode);
					fec_flag = 0;
					fec_mode = -1;
				}
				tmp++;
				OSAL_trace(eRTPP, eDebug, "fec_flag = %d, fec_mode = %d", fec_flag, fec_mode);
				break;
			case 'r': // recover
				OSAL_trace(eRTPP, eDebug, "recover port");
				recover = 1;
				break;
			case 'e': // record flag
				OSAL_trace(eRTPP, eDebug, "record flag");
				length = get_record_callid(tmp+1, &name, &tmp);
				if (length < 1) 
				{
					OSAL_trace(eRTPP, eError, "get record callid error");
					rtpp_reply_err(cookie,RTPP_ERR_RECORD_CALLID,fip,fport);
					return 0;
				}
				memset(record_callid, 0, RTPP_MAX_RECORD_CALLID);
				strncpy(record_callid, name, RTPP_MAX_RECORD_CALLID-1);
				record_callid[length] = '\0';
				record_flag = 1;
				tmp--;
				break;
			case 'b': //branche
				branche = atoi(tmp+1);
				if (branche != RTPP_BRANCHE_RIGHT  &&  branche != RTPP_BRANCHE_LEFT) {
					OSAL_trace(eRTPP, eWarn, "unkown rtpp branche %d", branche);
				}
				tmp++;
				break;
			case 'p'://port index
				port_index = atoi(tmp+1);
				if (port_index < 0 || port_index >= PORT_NUM_MAX) {
					OSAL_trace(eRTPP, eWarn, "unkown port index %d", port_index);
				}
				tmp++;
				break;
			default:
				OSAL_trace(eRTPP, eError, "unknown command option '%c'",*tmp);
				break;
   		}
	}
	//media from ip check
	if(inet_pton(AF_INET,ip,&intip) != 1){
		OSAL_trace(eRTPP, eError,"media from ip %s is invalid", ip);
		return -1;
	}

	if(video_flag){
		tmp = strchr(port,'/');
		if(tmp){
			*tmp = 0;
			tmp++;
			audioport = atoi(port);
			vedioport = atoi(tmp);
		}else{
			OSAL_trace(eRTPP, eError,"vedio flags but not vedio port");
			return -1;
		}
	}else{
		audioport = atoi(port);
		vedioport = 0;
	}
/*
	if(tsc_flag){
		if(argv[4]){
			tmp = strchr(argv[4],'@');
			if(tmp){
				*tmp = 0;
				tmp++;
				fromtag = argv[4];
				pt[0] = atoi(tmp);
			}
		}
		if(argv[5]){
			tmp = strchr(argv[5],'@');
			if(tmp){
				*tmp = 0;
				tmp++;
				totag = argv[5];
				pt[1] = atoi(tmp);
			}
		}
		
	}
*/
	if(tsc_flag){
		if(argv[4]){
			if(strchr(argv[4],'@')){
				fromtag = strtok(argv[4], "@");
				pt[0] = atoi(strtok(NULL, "@"));
			}
		}
		
		if(argv[5]){
			if(strchr(argv[5],'@')){
				totag = strtok(argv[5], "@");
				pt[1] = atoi(strtok(NULL, "@"));
			}
		}
		
		if(pt[0] == pt[1])
			tsc_flag = 0;
	}

	//OSAL_trace(eRTPP, eDebug, "fromtag is %s, totag is %s, pt[0] is %d, pt[1] is %d",fromtag, totag, pt[0], pt[1]);
	
	if(link_flags && (i = check_link_addr(link_ip)) < 0){
		OSAL_trace(eRTPP, eError, "ip %s is not in this rtpp",link_ip);
		rtpp_reply_err(cookie,RTPP_ERR_LINK_ADDR,fip,fport);
		return -1;
	}

	
	if(rtpp_find_session(callid, &ss) != 0){
		OSAL_trace (eRTPP, eInfo, "not find ss,u1 creat %s",callid);
		ss = rtpp_new_session(callid);
		if(NULL == ss){
			OSAL_trace (eRTPP, eError, "rtpp new session failed");
			rtpp_reply_err(cookie,RTPP_ERR_NO_SS,fip,fport);
			return -1;
		}

		//memset(ss->branche_is_initialized, 0, sizeof(ss->branche_is_initialized));
		ss->mod_id = mod_id;
		ss->ttlmode = RtppGlobals.ttlmode;
		ss->timeout = RtppGlobals.timeout;
		strcpy(ss->cookie,cookie);
		ss->from_ip = pMsg->param;
		strncpy(ss->f_tag,fromtag,RTPP_MAX_TAG_LEN-1);
		strncpy(ss->to_tag,totag,RTPP_MAX_TAG_LEN-1);
		strncpy(ss->notify,notify,RTPP_MAX_NOTIFY_LEN-1);
		
		rtpp_start_media_time(ss);

		//init fec
		if(fec_flag){
			if(fec_init(&(ss->fec_inst)) < 0){
				OSAL_trace(eRTPP, eError, "fail to init fec of directcall.");
				rtpp_free_session(ss);
				rtpp_reply_err(cookie,RTPP_ERR_INIT_FEC,fip,fport);
				return OSAL_ERROR;
			}
			else
				OSAL_trace(eRTPP, eInfo, "fec_inst is %p", ss->fec_inst);
		}
	}else {
		//init fec
		if(fec_flag){
			if(fec_init(&(ss->fec_inst)) < 0){
				OSAL_trace(eRTPP, eError, "fail to init fec of directcall.");
				rtpp_reply_err(cookie,RTPP_ERR_INIT_FEC,fip,fport);
				return OSAL_ERROR;
			}
			else
				OSAL_trace(eRTPP, eInfo, "fec_inst is %p", ss->fec_inst);
		}
	}

	//no "b" option, compatible with old version rtpc
	if (branche == -1) {
		if(!strcmp(ss->f_tag,fromtag)){
			branche = RTPP_BRANCHE_RIGHT;
		}else if(!strcmp(ss->f_tag,totag)){
			branche = RTPP_BRANCHE_LEFT;
		}
	}
		
	switch(branche){
	case RTPP_BRANCHE_RIGHT:
		//if (ss->branche_is_initialized[RTPP_BRANCHE_RIGHT] == OSAL_FALSE) {
		if (ss->right.audio[port_index].is_alloc_sk  == OSAL_FALSE) {
			res = rtpp_pop_port(RTPP_BRANCHE_RIGHT, port_index, mod_id,i,intip,audioport,vedioport,video_flag,asym_flags,tsc_flag, fec_mode, ss);
			if(res < 0){
				OSAL_trace(eRTPP, eError,"pop IP %d failed", i);
				rtpp_free_session(ss);
				rtpp_reply_err(cookie,RTPP_ERR_NO_RESORCE,fip,fport);
				return -1;
			}
			ss->right.audio[port_index].pt = pt[1];
			ss->left.audio[port_index].pt = pt[0];
			ss->create_time = time(NULL);

			ss->left.audio[port_index].jt_calc = ss->right.audio[port_index].jt_calc = RtppGlobals.jt_flag;
			
			if(video_flag){
				OSAL_trace(eRTPP, eSys,"U1(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d vedio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
					complete_flags,asym_flags,link_ip,ss->right.audio[port_index].p->port,ss->right.video[port_index].p->port,ss->right.audio[port_index].p->fd);
			}else{
				OSAL_trace(eRTPP, eSys,"U1(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
					complete_flags,asym_flags,link_ip,ss->right.audio[port_index].p->port,ss->right.audio[port_index].p->fd);
			}

			if(tsc_flag){
				if((ss->inst = Mixer_create_conference(ss)) == NULL){
					OSAL_trace(eRTPP, eError, "fail to create mixer conference");
					rtpp_free_session(ss);
					rtpp_reply_err(cookie,RTPP_ERR_CREAT_CONFERRENCE,fip,fport);				
					return OSAL_ERROR;
				}
				OSAL_trace(eRTPP, eDebug, "rtpp_creat_conference: session inst addr is %p", ss->inst);
				//add participant
				mp.m_pt = (mixer_codec_type_t)ss->right.audio[port_index].pt;
				if(ss->right.audio[port_index].mixed == 0){
					OSAL_trace(eRTPP, eDebug, "session inst addr is %p, pt is %d", ss->inst, mp.m_pt);	
					if((ss->right.audio[port_index].id = Mixer_add_participant(ss->inst, &mp)) < 0){
						OSAL_trace(eRTPP, eError, "fail to add mixer participant");
						rtpp_free_session(ss);
						rtpp_reply_err(cookie,RTPP_ERR_ADD_PARTICIPANT,fip,fport);					
						return OSAL_ERROR;
					}
					ss->right.audio[port_index].mixed = 1;
					OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", mp.m_pt, ss->to_tag, ss->right.audio[port_index].id);
				}			
			}
			rtpp_reply_port(cookie, RTPP_BRANCHE_RIGHT,port_index,ss->right.audio[port_index].p->port,(ss->right.video[port_index].p?ss->right.video[port_index].p->port:0),fip,fport);

			//ss->branche_is_initialized[RTPP_BRANCHE_RIGHT]  = OSAL_TRUE;
			ss->right.audio[port_index].is_alloc_sk = OSAL_TRUE;
			
		}else {
			if(ss->right.audio[port_index].pbak && recover){
				//delete participant
				if(tsc_flag){
					OSAL_trace(eRTPP, eInfo, "delete participant %s", ss->to_tag);
					if(ss->right.audio[port_index].pt >= 0){
						if(Mixer_remove_participant(ss->inst, ss->right.audio[port_index].id) < 0){							
							OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
							rtpp_free_session(ss);
							rtpp_reply_err(cookie,RTPP_ERR_DEL_PARTICIPANT,fip,fport);						
							return OSAL_ERROR;
						}
					}
					ss->right.audio[port_index].mixed = 0;
				}			
				rtpp_disselct_free_port(ss->mod_id,ss->right.audio[port_index].p);
				ss->right.audio[port_index].p = ss->right.audio[port_index].pbak;
				ss->right.audio[port_index].pbak = NULL;
				//rtpp_selct_port(ss->mod_id,tsc_flag,&ss->right.audio);
				if(video_flag){
					rtpp_disselct_free_port(ss->mod_id,ss->right.video[port_index].p);
					ss->right.video[port_index].p = ss->right.video[port_index].pbak;
					ss->right.video[port_index].pbak = NULL;
					//rtpp_selct_port(ss->mod_id,0,&ss->right.video);
				}
				if(video_flag){
					OSAL_trace(eRTPP, eSys,"recover U1(%d) [%s->%s] f[%d] a[%d] alloc audio %d vedio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
						complete_flags,asym_flags,ss->right.audio[port_index].p->port,ss->right.video[port_index].p->port,ss->right.audio[port_index].p->fd);
				}else{
					OSAL_trace(eRTPP, eSys,"recover U1(%d) [%s->%s] f[%d] a[%d] alloc audio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
						complete_flags,asym_flags,ss->right.audio[port_index].p->port,ss->right.audio[port_index].p->fd);
				}
				//add participant
				if(tsc_flag){			
					mp.m_pt = (mixer_codec_type_t)ss->right.audio[port_index].pt;
					if(ss->right.audio[port_index].mixed == 0){
						OSAL_trace(eRTPP, eDebug, "session inst addr is %p, pt is %d", ss->inst, mp.m_pt);	
						if((ss->right.audio[port_index].id = Mixer_add_participant(ss->inst, &mp)) < 0){
							OSAL_trace(eRTPP, eError, "fail to add mixer participant");
							rtpp_free_session(ss);
							rtpp_reply_err(cookie,RTPP_ERR_ADD_PARTICIPANT,fip,fport);					
							return OSAL_ERROR;
						}
						ss->right.audio[port_index].mixed = 1;
						OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", mp.m_pt, ss->to_tag, ss->right.audio[port_index].id);
					}	
				}			
			}
			else if((ss->right.audio[port_index].p->index == i || 0 == i) && (recover == 0)){
				ss->right.audio[port_index].fec_mode = fec_mode;
				rtpp_update_left_aport(intip,port_index, audioport,asym_flags,ss);
				if(video_flag) rtpp_update_left_vport(intip,port_index, vedioport,asym_flags,ss);
			}else if(recover == 0){
				//delete participant
				if(tsc_flag){
					OSAL_trace(eRTPP, eInfo, "delete participant %s", ss->to_tag);
					if(ss->right.audio[port_index].pt >= 0){
						if(Mixer_remove_participant(ss->inst, ss->right.audio[port_index].id) < 0){							
							OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
							rtpp_free_session(ss);
							rtpp_reply_err(cookie,RTPP_ERR_DEL_PARTICIPANT,fip,fport);						
							return OSAL_ERROR;
						}
					}
					ss->right.audio[port_index].mixed = 0;
				}

				//rtpp_disselct_port(ss->mod_id,ss->right.audio[port_index].p);
				ss->right.audio[port_index].pbak = ss->right.audio[port_index].p;
				if(video_flag){
					//rtpp_disselct_port(ss->mod_id,ss->right.video[port_index].p);
					ss->right.video[port_index].pbak = ss->right.video[port_index].p;
				}
				
				res = rtpp_pop_port(RTPP_BRANCHE_RIGHT,port_index,mod_id,i,intip,audioport,vedioport,video_flag,asym_flags,tsc_flag,fec_mode,ss);
				if(res < 0){
					OSAL_trace(eRTPP, eError,"pop IP %d failed", i);
					rtpp_free_session(ss);
					rtpp_reply_err(cookie,RTPP_ERR_NO_RESORCE,fip,fport);
					return -1;
				}
				if(video_flag){
					OSAL_trace(eRTPP, eSys,"U1(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d vedio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
						complete_flags,asym_flags,link_ip,ss->right.audio[port_index].p->port,ss->right.video[port_index].p->port,ss->right.audio[port_index].p->fd);
				}else{
					OSAL_trace(eRTPP, eSys,"U1(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
						complete_flags,asym_flags,link_ip,ss->right.audio[port_index].p->port,ss->right.audio[port_index].p->fd);
				}
				//add participant
				if(tsc_flag){			
					mp.m_pt = (mixer_codec_type_t)ss->right.audio[port_index].pt;
					if(ss->right.audio[port_index].mixed == 0){
						OSAL_trace(eRTPP, eDebug, "session inst addr is %p, pt is %d", ss->inst, mp.m_pt);	
						if((ss->right.audio[port_index].id = Mixer_add_participant(ss->inst, &mp)) < 0){
							OSAL_trace(eRTPP, eError, "fail to add mixer participant");
							rtpp_free_session(ss);
							rtpp_reply_err(cookie,RTPP_ERR_ADD_PARTICIPANT,fip,fport);					
							return OSAL_ERROR;
						}
						ss->right.audio[port_index].mixed = 1;
							OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", mp.m_pt, ss->to_tag, ss->right.audio[port_index].id);
						}	
				}
			}
			rtpp_reply_port(cookie, RTPP_BRANCHE_RIGHT, port_index, ss->right.audio[port_index].p->port,(ss->right.video[port_index].p?ss->right.video[port_index].p->port:0),fip,fport);
		}
		
		break;

	case RTPP_BRANCHE_LEFT:
		//if (ss->branche_is_initialized[RTPP_BRANCHE_LEFT] == OSAL_FALSE) {
		if (ss->left.audio[port_index].is_alloc_sk == OSAL_FALSE) {
			res = rtpp_pop_port(RTPP_BRANCHE_LEFT,port_index, mod_id,i,intip,audioport,vedioport,video_flag,asym_flags,tsc_flag,fec_mode, ss);
			if(res < 0){
				OSAL_trace(eRTPP, eError,"pop IP %d failed", i);
				rtpp_free_session(ss);
				rtpp_reply_err(cookie,RTPP_ERR_NO_RESORCE,fip,fport);
				return -1;
			}
			if(video_flag){
				OSAL_trace(eRTPP, eSys,"U2(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d vedio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
					complete_flags,asym_flags,link_ip,ss->left.audio[port_index].p->port,ss->left.video[port_index].p->port,ss->left.audio[port_index].p->fd);
			}else{
				OSAL_trace(eRTPP, eSys,"U2(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
					complete_flags,asym_flags,link_ip,ss->left.audio[port_index].p->port,ss->left.audio[port_index].p->fd);
			}
			//add participant
			if(tsc_flag){
				//add participant
				mp.m_pt = (mixer_codec_type_t)ss->left.audio[port_index].pt;
				if(ss->left.audio[port_index].mixed == 0){
					OSAL_trace(eRTPP, eDebug, "session inst addr is %p, pt is %d", ss->inst, mp.m_pt);	
					if((ss->left.audio[port_index].id = Mixer_add_participant(ss->inst, &mp)) < 0){
						OSAL_trace(eRTPP, eError, "fail to add mixer participant");
						rtpp_free_session(ss);
						rtpp_reply_err(cookie,RTPP_ERR_ADD_PARTICIPANT,fip,fport);							
						return OSAL_ERROR;
					}
					ss->left.audio[port_index].mixed = 1;
					OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", mp.m_pt, ss->f_tag, ss->left.audio[port_index].id);
				}			
			}	
			rtpp_reply_port(cookie, RTPP_BRANCHE_LEFT, port_index, ss->left.audio[port_index].p->port,(ss->left.video[port_index].p?ss->left.video[port_index].p->port:0),fip,fport);
			//ss->branche_is_initialized[RTPP_BRANCHE_LEFT]  = OSAL_TRUE;
			ss->left.audio[port_index].is_alloc_sk = OSAL_TRUE;
		}else {
			if(ss->left.audio[port_index].p->index == i || 0 == i){
				ss->left.audio[port_index].fec_mode = fec_mode;
				rtpp_update_right_aport(intip,port_index, audioport,asym_flags,ss);
				if(video_flag) rtpp_update_right_vport(intip,port_index, vedioport,asym_flags,ss);
			}else{
				//delete participant
				if(tsc_flag){
					OSAL_trace(eRTPP, eInfo, "delete participant %s", ss->f_tag);
					if(ss->left.audio[port_index].pt >= 0){
						if(Mixer_remove_participant(ss->inst, ss->left.audio[port_index].id) < 0){							
							OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
							rtpp_free_session(ss);
							rtpp_reply_err(cookie,RTPP_ERR_DEL_PARTICIPANT,fip,fport);						
							return OSAL_ERROR;
						}
					}
					ss->left.audio[port_index].mixed = 0;
				}
				rtpp_disselct_free_port(ss->mod_id,ss->left.audio[port_index].p);
				if(video_flag) rtpp_disselct_free_port(ss->mod_id,ss->left.video[port_index].p);
				res = rtpp_pop_port(RTPP_BRANCHE_LEFT,port_index, mod_id,i,intip,audioport,vedioport,video_flag,asym_flags,tsc_flag, fec_mode, ss);
				if(res < 0){
					OSAL_trace(eRTPP, eError,"pop IP %d failed", i);
					rtpp_free_session(ss);
					rtpp_reply_err(cookie,RTPP_ERR_NO_RESORCE,fip,fport);
					return -1;
				}
				if(video_flag){
					OSAL_trace(eRTPP, eSys,"U2(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d vedio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
						complete_flags,asym_flags,link_ip,ss->left.audio[port_index].p->port,ss->left.video[port_index].p->port,ss->left.audio[port_index].p->fd);
				}else{
					OSAL_trace(eRTPP, eSys,"U2(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
						complete_flags,asym_flags,link_ip,ss->left.audio[port_index].p->port,ss->left.audio[port_index].p->fd);
				}
				//add participant
				if(tsc_flag){			
					mp.m_pt = (mixer_codec_type_t)ss->left.audio[port_index].pt;
					if(ss->left.audio[port_index].mixed == 0){
						OSAL_trace(eRTPP, eDebug, "session inst addr is %p, pt is %d", ss->inst, mp.m_pt);	
						if((ss->left.audio[port_index].id = Mixer_add_participant(ss->inst, &mp)) < 0){
							OSAL_trace(eRTPP, eError, "fail to add mixer participant");
							rtpp_free_session(ss);
							rtpp_reply_err(cookie,RTPP_ERR_ADD_PARTICIPANT,fip,fport);					
							return OSAL_ERROR;
						}
						ss->left.audio[port_index].mixed = 1;
						OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", mp.m_pt, ss->f_tag, ss->left.audio[port_index].id);
					}	
				}				
			}
			rtpp_reply_port(cookie, RTPP_BRANCHE_LEFT, port_index, ss->left.audio[port_index].p->port,(ss->left.video[port_index].p?ss->left.video[port_index].p->port:0),fip,fport);
		}
		break;

	default:
		OSAL_trace (eRTPP, eError, "unKnow branche id  %d", branche);
		break;
	}

#if 0		
	if((res = rtpp_find_session(callid, &ss)) != 0){
		OSAL_trace (eRTPP, eInfo, "not find ss,u1 creat %s",callid);
		ss = rtpp_new_session(callid);
		if(NULL == ss){
			OSAL_trace (eRTPP, eError, "rtpp new session failed");
			rtpp_reply_err(cookie,RTPP_ERR_NO_SS,fip,fport);
			return -1;
		}
		
		ss->mod_id = mod_id;
		ss->ttlmode = RtppGlobals.ttlmode;
		ss->timeout = RtppGlobals.timeout;
		strcpy(ss->cookie,cookie);
		ss->from_ip = pMsg->param;
		strncpy(ss->f_tag,fromtag,RTPP_MAX_TAG_LEN-1);
		strncpy(ss->to_tag,totag,RTPP_MAX_TAG_LEN-1);
		strncpy(ss->notify,notify,RTPP_MAX_NOTIFY_LEN-1);
		
		rtpp_start_media_time(ss);
		

		res = rtpp_pop_port(RTPP_BRANCHE_RIGHT,mod_id,i,intip,audioport,vedioport,video_flag,asym_flags,tsc_flag, fec_mode, ss);
		if(res < 0){
			OSAL_trace(eRTPP, eError,"pop IP %d failed", i);
			rtpp_free_session(ss);
			rtpp_reply_err(cookie,RTPP_ERR_NO_RESORCE,fip,fport);
			return -1;
		}
		ss->right.audio[port_index].pt = pt[1];
		ss->left.audio[port_index].pt = pt[0];
		ss->create_time = time(NULL);

		ss->left.audio[port_index].jt_calc = ss->right.audio[port_index].jt_calc = RtppGlobals.jt_flag;
		
		if(video_flag){
			OSAL_trace(eRTPP, eSys,"U1(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d vedio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
				complete_flags,asym_flags,link_ip,ss->right.audio[port_index].p->port,ss->right.video[port_index].p->port,ss->right.audio[port_index].p->fd);
		}else{
			OSAL_trace(eRTPP, eSys,"U1(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
				complete_flags,asym_flags,link_ip,ss->right.audio[port_index].p->port,ss->right.audio[port_index].p->fd);
		}

		//init fec
		if(fec_flag){
			if(fec_init(&(ss->fec_inst)) < 0){
				OSAL_trace(eRTPP, eError, "fail to init fec of directcall.");
				rtpp_free_session(ss);
				rtpp_reply_err(cookie,RTPP_ERR_INIT_FEC,fip,fport);
				return OSAL_ERROR;
			}
			else
				OSAL_trace(eRTPP, eInfo, "fec_inst is %p", ss->fec_inst);
		}

		// create conference if tsc_flag  is 1
		if(tsc_flag){
			if((ss->inst = Mixer_create_conference(ss)) == NULL){
				OSAL_trace(eRTPP, eError, "fail to create mixer conference");
				rtpp_free_session(ss);
				rtpp_reply_err(cookie,RTPP_ERR_CREAT_CONFERRENCE,fip,fport);				
				return OSAL_ERROR;
			}
			OSAL_trace(eRTPP, eDebug, "rtpp_creat_conference: session inst addr is %p", ss->inst);
			//add participant
			mp.m_pt = (mixer_codec_type_t)ss->right.audio[port_index].pt;
			if(ss->right.audio[port_index].mixed == 0){
				OSAL_trace(eRTPP, eDebug, "session inst addr is %p, pt is %d", ss->inst, mp.m_pt);	
				if((ss->right.audio[port_index].id = Mixer_add_participant(ss->inst, &mp)) < 0){
					OSAL_trace(eRTPP, eError, "fail to add mixer participant");
					rtpp_free_session(ss);
					rtpp_reply_err(cookie,RTPP_ERR_ADD_PARTICIPANT,fip,fport);					
					return OSAL_ERROR;
				}
				ss->right.audio[port_index].mixed = 1;
				OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", mp.m_pt, ss->to_tag, ss->right.audio[port_index].id);
			}			
		}
		
		rtpp_reply_port(cookie,ss->right.audio[port_index].p->port,(ss->right.video[port_index].p?ss->right.video[port_index].p->port:0),fip,fport);
	}
	else if(1 == res){
		if(ss->right.audio[port_index].pbak && recover){
			//delete participant
			if(tsc_flag){
				OSAL_trace(eRTPP, eInfo, "delete participant %s", ss->to_tag);
				if(ss->right.audio[port_index].pt >= 0){
					if(Mixer_remove_participant(ss->inst, ss->right.audio[port_index].id) < 0){							
						OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
						rtpp_free_session(ss);
						rtpp_reply_err(cookie,RTPP_ERR_DEL_PARTICIPANT,fip,fport);						
						return OSAL_ERROR;
					}
				}
				ss->right.audio[port_index].mixed = 0;
			}			
			rtpp_disselct_free_port(ss->mod_id,ss->right.audio[port_index].p);
			ss->right.audio[port_index].p = ss->right.audio[port_index].pbak;
			ss->right.audio[port_index].pbak = NULL;
			//rtpp_selct_port(ss->mod_id,tsc_flag,&ss->right.audio);
			if(video_flag){
				rtpp_disselct_free_port(ss->mod_id,ss->right.video[port_index].p);
				ss->right.video[port_index].p = ss->right.video[port_index].pbak;
				ss->right.video[port_index].pbak = NULL;
				//rtpp_selct_port(ss->mod_id,0,&ss->right.video);
			}
			if(video_flag){
				OSAL_trace(eRTPP, eSys,"recover U1(%d) [%s->%s] f[%d] a[%d] alloc audio %d vedio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
					complete_flags,asym_flags,ss->right.audio[port_index].p->port,ss->right.video[port_index].p->port,ss->right.audio[port_index].p->fd);
			}else{
				OSAL_trace(eRTPP, eSys,"recover U1(%d) [%s->%s] f[%d] a[%d] alloc audio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
					complete_flags,asym_flags,ss->right.audio[port_index].p->port,ss->right.audio[port_index].p->fd);
			}
			//add participant
			if(tsc_flag){			
				mp.m_pt = (mixer_codec_type_t)ss->right.audio[port_index].pt;
				if(ss->right.audio[port_index].mixed == 0){
					OSAL_trace(eRTPP, eDebug, "session inst addr is %p, pt is %d", ss->inst, mp.m_pt);	
					if((ss->right.audio[port_index].id = Mixer_add_participant(ss->inst, &mp)) < 0){
						OSAL_trace(eRTPP, eError, "fail to add mixer participant");
						rtpp_free_session(ss);
						rtpp_reply_err(cookie,RTPP_ERR_ADD_PARTICIPANT,fip,fport);					
						return OSAL_ERROR;
					}
					ss->right.audio[port_index].mixed = 1;
					OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", mp.m_pt, ss->to_tag, ss->right.audio[port_index].id);
				}	
			}			
		}
		else if((ss->right.audio[port_index].p->index == i || -1 == i) && (recover == 0)){
			ss->right.audio[port_index].fec_mode = fec_mode;
			rtpp_update_left_aport(intip,audioport,asym_flags,ss);
			if(video_flag) rtpp_update_left_vport(intip,vedioport,asym_flags,ss);
		}else if(recover == 0){
			//delete participant
			if(tsc_flag){
				OSAL_trace(eRTPP, eInfo, "delete participant %s", ss->to_tag);
				if(ss->right.audio[port_index].pt >= 0){
					if(Mixer_remove_participant(ss->inst, ss->right.audio[port_index].id) < 0){							
						OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
						rtpp_free_session(ss);
						rtpp_reply_err(cookie,RTPP_ERR_DEL_PARTICIPANT,fip,fport);						
						return OSAL_ERROR;
					}
				}
				ss->right.audio[port_index].mixed = 0;
			}
			//rtpp_disselct_port(ss->mod_id,ss->right.audio[port_index].p);
			ss->right.audio[port_index].pbak = ss->right.audio[port_index].p;
			if(video_flag){
				//rtpp_disselct_port(ss->mod_id,ss->right.video[port_index].p);
				ss->right.video[port_index].pbak = ss->right.video[port_index].p;
			}
			
			res = rtpp_pop_port(RTPP_BRANCHE_RIGHT,mod_id,i,intip,audioport,vedioport,video_flag,asym_flags,tsc_flag,fec_mode,ss);
			if(res < 0){
				OSAL_trace(eRTPP, eError,"pop IP %d failed", i);
				rtpp_free_session(ss);
				rtpp_reply_err(cookie,RTPP_ERR_NO_RESORCE,fip,fport);
				return -1;
			}
			if(video_flag){
				OSAL_trace(eRTPP, eSys,"U1(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d vedio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
					complete_flags,asym_flags,link_ip,ss->right.audio[port_index].p->port,ss->right.video[port_index].p->port,ss->right.audio[port_index].p->fd);
			}else{
				OSAL_trace(eRTPP, eSys,"U1(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
					complete_flags,asym_flags,link_ip,ss->right.audio[port_index].p->port,ss->right.audio[port_index].p->fd);
			}
			//add participant
			if(tsc_flag){			
				mp.m_pt = (mixer_codec_type_t)ss->right.audio[port_index].pt;
				if(ss->right.audio[port_index].mixed == 0){
					OSAL_trace(eRTPP, eDebug, "session inst addr is %p, pt is %d", ss->inst, mp.m_pt);	
					if((ss->right.audio[port_index].id = Mixer_add_participant(ss->inst, &mp)) < 0){
						OSAL_trace(eRTPP, eError, "fail to add mixer participant");
						rtpp_free_session(ss);
						rtpp_reply_err(cookie,RTPP_ERR_ADD_PARTICIPANT,fip,fport);					
						return OSAL_ERROR;
					}
					ss->right.audio[port_index].mixed = 1;
					OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", mp.m_pt, ss->to_tag, ss->right.audio[port_index].id);
				}	
			}
		}
		rtpp_reply_port(cookie,ss->right.audio[port_index].p->port,(ss->right.video[port_index].p?ss->right.video[port_index].p->port:0),fip,fport);
	}
	else{
		if(!ss->left.audio[port_index].p){
			res = rtpp_pop_port(RTPP_BRANCHE_LEFT,mod_id,i,intip,audioport,vedioport,video_flag,asym_flags,tsc_flag,fec_mode, ss);
			if(res < 0){
				OSAL_trace(eRTPP, eError,"pop IP %d failed", i);
				rtpp_free_session(ss);
				rtpp_reply_err(cookie,RTPP_ERR_NO_RESORCE,fip,fport);
				return -1;
			}
			if(video_flag){
				OSAL_trace(eRTPP, eSys,"U2(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d vedio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
					complete_flags,asym_flags,link_ip,ss->left.audio[port_index].p->port,ss->left.video[port_index].p->port,ss->left.audio[port_index].p->fd);
			}else{
				OSAL_trace(eRTPP, eSys,"U2(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
					complete_flags,asym_flags,link_ip,ss->left.audio[port_index].p->port,ss->left.audio[port_index].p->fd);
			}
			//add participant
			if(tsc_flag){
				//add participant
				mp.m_pt = (mixer_codec_type_t)ss->left.audio[port_index].pt;
				if(ss->left.audio[port_index].mixed == 0){
					OSAL_trace(eRTPP, eDebug, "session inst addr is %p, pt is %d", ss->inst, mp.m_pt);	
					if((ss->left.audio[port_index].id = Mixer_add_participant(ss->inst, &mp)) < 0){
						OSAL_trace(eRTPP, eError, "fail to add mixer participant");
						rtpp_free_session(ss);
						rtpp_reply_err(cookie,RTPP_ERR_ADD_PARTICIPANT,fip,fport);							
						return OSAL_ERROR;
					}
					ss->left.audio[port_index].mixed = 1;
					OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", mp.m_pt, ss->f_tag, ss->left.audio[port_index].id);
				}			
			}			
		}
		else{
			if(ss->left.audio[port_index].p->index == i || -1 == i){
				ss->left.audio[port_index].fec_mode = fec_mode;
				rtpp_update_right_aport(intip,audioport,asym_flags,ss);
				if(video_flag) rtpp_update_right_vport(intip,vedioport,asym_flags,ss);
			}else{
				//delete participant
				if(tsc_flag){
					OSAL_trace(eRTPP, eInfo, "delete participant %s", ss->f_tag);
					if(ss->left.audio[port_index].pt >= 0){
						if(Mixer_remove_participant(ss->inst, ss->left.audio[port_index].id) < 0){							
							OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
							rtpp_free_session(ss);
							rtpp_reply_err(cookie,RTPP_ERR_DEL_PARTICIPANT,fip,fport);						
							return OSAL_ERROR;
						}
					}
					ss->left.audio[port_index].mixed = 0;
				}			
				rtpp_disselct_free_port(ss->mod_id,ss->left.audio[port_index].p);
				if(video_flag) rtpp_disselct_free_port(ss->mod_id,ss->left.video[port_index].p);
				res = rtpp_pop_port(RTPP_BRANCHE_LEFT,mod_id,i,intip,audioport,vedioport,video_flag,asym_flags,tsc_flag, fec_mode, ss);
				if(res < 0){
					OSAL_trace(eRTPP, eError,"pop IP %d failed", i);
					rtpp_free_session(ss);
					rtpp_reply_err(cookie,RTPP_ERR_NO_RESORCE,fip,fport);
					return -1;
				}
				if(video_flag){
					OSAL_trace(eRTPP, eSys,"U2(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d vedio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
						complete_flags,asym_flags,link_ip,ss->left.audio[port_index].p->port,ss->left.video[port_index].p->port,ss->left.audio[port_index].p->fd);
				}else{
					OSAL_trace(eRTPP, eSys,"U2(%d) [%s->%s] f[%d] a[%d] ip [%s] alloc audio %d fd:%d",mod_id,ss->f_tag,ss->to_tag,
						complete_flags,asym_flags,link_ip,ss->left.audio[port_index].p->port,ss->left.audio[port_index].p->fd);
				}
				//add participant
				if(tsc_flag){			
					mp.m_pt = (mixer_codec_type_t)ss->left.audio[port_index].pt;
					if(ss->left.audio[port_index].mixed == 0){
						OSAL_trace(eRTPP, eDebug, "session inst addr is %p, pt is %d", ss->inst, mp.m_pt);	
						if((ss->left.audio[port_index].id = Mixer_add_participant(ss->inst, &mp)) < 0){
							OSAL_trace(eRTPP, eError, "fail to add mixer participant");
							rtpp_free_session(ss);
							rtpp_reply_err(cookie,RTPP_ERR_ADD_PARTICIPANT,fip,fport);					
							return OSAL_ERROR;
						}
						ss->left.audio[port_index].mixed = 1;
						OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", mp.m_pt, ss->f_tag, ss->left.audio[port_index].id);
					}	
				}				
			}
		}
		rtpp_reply_port(cookie,ss->left.audio[port_index].p->port,(ss->left.video[port_index].p?ss->left.video[port_index].p->port:0),fip,fport);
	}

#endif 

	rtpp_check_record(RtppGlobals.record_dir, record_flag, record_callid, ss);
	
	//set flags
	ss->vflag = video_flag;
	ss->tsc_flag = tsc_flag;
	ss->fec_flag = fec_flag;
	ss->record_flag = record_flag;
	
	if(!ss->finish && complete_flags){
		ss->connect_time = time(NULL);
		ss->finish = complete_flags;
	}

	if(ss->fec_flag && !ss->fec_inst) {
		if(fec_init(&(ss->fec_inst)) < 0){
			OSAL_trace(eRTPP, eError, "fauler to initial fec instance..");
			rtpp_free_session(ss);
			rtpp_reply_err(cookie,RTPP_ERR_INIT_FEC,fip,fport);
			return OSAL_ERROR;
		}
		OSAL_trace(eRTPP, eInfo, "succeed to initial fec instance.");
	}

	/*
	RtppGlobals.stats_.concurrency++;
	if(video_flag)
		RtppGlobals.stats_.ipConcurrency += 4;
	else
		RtppGlobals.stats_.ipConcurrency += 2;
	*/

	gettimeofday(&ss->startTime,NULL);
		
	return OSAL_OK;
}

OSAL_INT32 rtpp_us_proc (OSAL_INT32 iFec,OSAL_INT32 iModel,OSAL_CHAR* remoteIp,OSAL_INT32 remotePort)
{
	rtpp_session_t *ss = &RtppGlobals.htest.ss[iFec];
	OSAL_CHAR lIP[MAX_IP_LEN] = {0};
	OSAL_CHAR rIP[MAX_IP_LEN] = {0};
	OSAL_INT32 lPort = 1,rPort = 1;
	OSAL_INT32 lAsy = 0,rAsy = 0;
	OSAL_INT32 linitip = 0,rinitip = 0;

	//µÚÒ»ÌøÓÒ²à½âÂë,×ó²à±àÂë,µÚ¶þÌøÓÒ²à±àÂë£¬×ó²à½âÂë
	if(iModel == 0)
	{
		memcpy(rIP,remoteIp,strlen(remoteIp));	
		if(inet_pton(AF_INET,rIP,&rinitip) != 1){
			printf( "error remote rtpp ip\n");
			return -1;
		}
		rPort= remotePort;
		rAsy = 1;
		ss->right.audio[0].fip = rinitip;
		ss->right.audio[0].fport = htons(rPort);
		ss->right.audio[0].frtcpport =  htons(rPort+1);
		ss->right.audio[0].asym = rAsy;
		ss->left.audio[0].asym = lAsy;
		if(iFec){
		ss->left.audio[0].fec_mode = FEC_ENCODE_PKT;
		ss->right.audio[0].fec_mode = FEC_DECODE_PKT;
		}
	}else  if(iModel == 1){
		memcpy(lIP,remoteIp,strlen(remoteIp));
		if(inet_pton(AF_INET,lIP,&linitip) != 1){
			printf( "error remote rtpp ip\n");
			return -1;
		}
		lPort= remotePort;
		lAsy = 1;
		ss->left.audio[0].fip = linitip;
		ss->left.audio[0].fport = htons(lPort);
		ss->left.audio[0].frtcpport =  htons(lPort+1);
		ss->left.audio[0].asym = lAsy;
		ss->right.audio[0].asym = rAsy;
		if(iFec){
			ss->left.audio[0].fec_mode = FEC_DECODE_PKT;
			ss->right.audio[0].fec_mode = FEC_ENCODE_PKT;
		}
	}
	ss->finish = 1;	
	printf("US Left fip:%s-%d fport:%d fec_mode:%d fd:%d\n",lIP,ss->left.audio[0].fip,ss->left.audio[0].fport,ss->left.audio[0].fec_mode,ss->left.audio[0].p->fd);
	printf("US Right fip:%s-%d fport:%d fec_mode:%d fd:%d\n",rIP,ss->right.audio[0].fip,ss->right.audio[0].fport,ss->right.audio[0].fec_mode,ss->right.audio[0].p->fd);

	return OSAL_OK;
}

OSAL_INT32 rtpp_d_proc (OSAL_msgHdr *pMsg)
{
	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_INT32 argc,res;
	double left_loss = 100.0;
	double right_loss = 100.0;
	OSAL_INT32 left_pt = -1;
	OSAL_INT32 right_pt = -1;
	struct in_addr left_sin;
	struct in_addr right_sin;
	char left_mgw[16] = "";
	char right_mgw[16] = "";
	OSAL_UINT32 left_rtp_recv = 0,left_recv_bytes;
	OSAL_UINT32 left_rtp_send = 0,left_send_bytes;
	OSAL_UINT32 right_rtp_recv = 0,right_recv_bytes;
	OSAL_UINT32 right_rtp_send = 0,right_send_bytes;
	OSAL_INT32 fip = pMsg->param;
	OSAL_UINT16 fport = pMsg->param2;
	OSAL_CHAR callid[RTPP_MAX_CALLID_LEN];
	rtpp_session_t *ss;
	OSAL_CHAR *tmp;
	OSAL_INT32 delete_record_file = 0;
	OSAL_INT32 notice_to_rtpc = 0;
	OSAL_INT32 release_branche_only = 0;
	OSAL_INT32 release_port_only = 0;
	OSAL_INT32 branche = RTPP_BRANCHE_ALL;
	OSAL_INT32 port_index = 0;
	OSAL_CHAR *cookie,*op,*fromtag,*totag,*transmsg;
	struct sockaddr_in raddr;
	OSAL_CHAR *msg = (OSAL_CHAR  *)pMsg->pContent;
	OSAL_INT32 len = pMsg->contentLen;
	int i;
	OSAL_INT32 fromIp;

	command_parse(msg,len,argv,&argc);

	raddr.sin_family = AF_INET;
	raddr.sin_addr.s_addr = fip;
	raddr.sin_port = fport;

	//modify for transparent index to rtpp 20160512
	if(5 != argc){
	//modify end
	//if(4 != argc){
		OSAL_trace (eRTPP, eError, "err format %s",msg);
		return -1;
	}else{
		//cookie op ip port from to notify content
		cookie = argv[0];
		op = argv[1];
		fromtag = argv[2];
		totag = argv[3];
		//add for transparent index to rtpp 20160512
		transmsg = argv[4];
		// add end
	}
	
   	if(get_callid(cookie,callid) < 0){
   		OSAL_trace (eRTPP, eError, "callid failed %s",msg);
   		return -1;
   	}

	//op proc
	for(tmp = op +1; *tmp; tmp++){
		switch (*tmp |= 32){
			case 'e': 
				delete_record_file = 1;
				break;

			case 's': 
				notice_to_rtpc = 1;
				break;

			case 'b':
				release_branche_only = 1;
				branche = atoi(tmp+1);
				if (branche != RTPP_BRANCHE_RIGHT  &&  branche != RTPP_BRANCHE_LEFT) {
					OSAL_trace(eRTPP, eWarn, "unkown rtpp branche %d", branche);
				}
				tmp++;
				break;
			case 'p':
				release_port_only = 1;
				port_index = atoi(tmp+1);
				if (port_index < 0  ||  port_index >= PORT_NUM_MAX) {
					OSAL_trace(eRTPP, eWarn, "unkown rtpp branche %d", branche);
				}
				tmp++;
				break;
				
			default:
				OSAL_trace(eRTPP, eError, "unknown command option '%c'",*tmp);
				break;
   		}
	}

	
	if(rtpp_find_session(callid,&ss) != 0){
		OSAL_trace (eRTPP, eWarn, "command d not find ss callid:%s,from:%s,to:%s",callid,fromtag,totag);
		rtpp_reply_err(cookie,RTPP_ERR_NO_SS,fip,fport);
		return -1;
	}else{
		//OSAL_trace(eRTPP, eSys,"(%d) rtpp del [%s->%s] fd %d<-->%d",pMsg->msgSubId,ss->f_tag,ss->to_tag,ss->left.audio[0].p->fd,ss->right.audio[0].p->fd);
		OSAL_trace(eRTPP, eSys,"(%d) rtpp del [%s->%s]",pMsg->msgSubId,ss->f_tag,ss->to_tag);
		if (release_branche_only && release_port_only ) {
			
			rtpp_rc_end(ss->branches[branche].audio[port_index].rcctr);
			rtpp_jt_end(&ss->branches[branche].audio[port_index],ss);
			rtpp_ssrc_end(&ss->branches[branche].audio[port_index]);
			
			if (ss->branches[branche].audio[port_index].rrcs != OSAL_NULL) rclose(ss->branches[branche].audio[port_index].rrcs);

			if(ss->branches[branche].audio[port_index].p) rtpp_disselct_free_port(ss->mod_id,ss->branches[branche].audio[port_index].p);
			if(ss->branches[branche].video[port_index].p) rtpp_disselct_free_port(ss->mod_id,ss->branches[branche].video[port_index].p);

			rtpp_d_reply_ok(cookie, branche, port_index, fip, fport);

			return OSAL_OK;
		}
		if(delete_record_file){
			for (i = 0; i < PORT_NUM_MAX; i++) {
				if(ss->left.audio[i].rrcs != OSAL_NULL){
					rclose(ss->left.audio[i].rrcs);
					remove((ss->left.audio[i].rrcs)->rpath);
					ss->left.audio[i].rrcs = OSAL_NULL;
				}
				if(ss->right.audio[i].rrcs != OSAL_NULL){
					rclose(ss->right.audio[i].rrcs);
					remove((ss->right.audio[i].rrcs)->rpath);
					ss->right.audio[i].rrcs = OSAL_NULL;
				}			
			}
		}
		
		if(notice_to_rtpc){
			for (i = 0; i < PORT_NUM_MAX; i++) {
				left_sin.s_addr = ss->left.audio[i].fip;
				right_sin.s_addr = ss->right.audio[i].fip;
				strncpy(left_mgw, inet_ntoa(left_sin), 16);
				strncpy(right_mgw, inet_ntoa(right_sin), 16);
				rtpp_get_statistics(ss, &left_loss, &right_loss, &left_pt, &right_pt);			
				left_rtp_recv += ss->left.audio[i].recv_packets;
				left_rtp_send += ss->left.audio[i].send_packets;
				right_rtp_recv += ss->right.audio[i].recv_packets;
				right_rtp_send += ss->right.audio[i].send_packets;
				left_recv_bytes += ss->left.audio[i].recv_bytes;
				left_send_bytes += ss->left.audio[i].send_bytes;
				right_recv_bytes += ss->right.audio[i].recv_bytes;
				right_send_bytes += ss->right.audio[i].send_bytes;
			}
		}
		ss->release_reason = 1;
		
		/*
		RtppGlobals.stats_.concurrency--;
		if(ss->vflag)
			RtppGlobals.stats_.ipConcurrency -= 4;
		else
			RtppGlobals.stats_.ipConcurrency -= 2;
		*/
		gettimeofday(&ss->endTime,NULL);
		if(notice_to_rtpc){
		/*
		*ÉÏ±¨»á»°Á÷Á¿ÐÅÏ¢
		*/
			OSAL_CHAR billInfo[64] = {0};	
			fromIp = ss->from_ip;
			sprintf(billInfo,"%s %u %u",ss->call_id,left_recv_bytes+right_recv_bytes,left_send_bytes+right_send_bytes);
			OSAL_trace (eRTPP, eDebug, "billinfo %s",msg);
			rtpp_send_msg_to_notify(RTPP_REPORT_BILL,billInfo,fromIp);
		}
		rtpp_free_session(ss);
		if(notice_to_rtpc){
			rtpp_d_reply_s_ok(cookie,RTPP_BRANCHE_ALL, PORT_ALL,fip, fport, left_loss, right_loss, left_pt, right_pt, left_mgw, right_mgw,
				left_rtp_recv,right_rtp_recv,left_rtp_send,right_rtp_send,transmsg,
				left_recv_bytes+right_recv_bytes,left_send_bytes+right_send_bytes);
		}
		else
			rtpp_d_reply_ok(cookie, RTPP_BRANCHE_ALL, PORT_ALL, fip, fport);
	}
	return OSAL_OK;
}


OSAL_INT32 rtpp_e_proc (OSAL_msgHdr *pMsg)
{
	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_INT32 argc,res;
	OSAL_INT32 fip = pMsg->param;
	OSAL_INT16 fport = pMsg->param2;
	OSAL_CHAR callid[RTPP_MAX_CALLID_LEN];
	OSAL_CHAR *tmp;
    /* delete by liujianfeng for not used on 2016-1-19 13:31:22 */
    //#if 0
	OSAL_INT32 e_fec_flag = 0;
    //#endif
    /* delete by liujianfeng end */
	OSAL_INT32 e_record_flag = 0;
	OSAL_INT32 e_complete_flags = 0;
	OSAL_INT32 e_calleeMedia_flags = 0;
	OSAL_CHAR *name;
	OSAL_CHAR record_callid[RTPP_MAX_RECORD_CALLID];
	OSAL_CHAR calleeMedia[32] = {0};
	OSAL_CHAR calleeMediaIp[RTPP_MAX_IP_LEN] = {0};
	OSAL_CHAR calleeMediaPort[8] = {0};
	OSAL_CHAR calleeMediaVPort[8] = {0};
	OSAL_INT32 length;
	rtpp_session_t *ss;
	OSAL_CHAR *cookie,*op,*fromtag,*totag;
	struct sockaddr_in raddr;
	OSAL_CHAR *msg = (OSAL_CHAR  *)pMsg->pContent;
	OSAL_INT32 len = pMsg->contentLen;

	command_parse(msg,len,argv,&argc);

	raddr.sin_family = AF_INET;
	raddr.sin_addr.s_addr = fip;
	raddr.sin_port = fport;
	
	if(4 != argc){
		OSAL_trace (eRTPP, eError, "err format %s",msg);
		return -1;
	}else{
		//cookie op ip port from to notify content
		cookie = argv[0];
		op = argv[1];
		fromtag = argv[2];
		totag = argv[3];
	}
	
   	if(get_callid(cookie,callid) < 0){
   		OSAL_trace (eRTPP, eError, "callid failed %s",msg);
   		return -1;
   	}

	//op proc
	for(tmp = op +1; *tmp; tmp++){
		switch (*tmp |= 32){
			case 'x':
				e_fec_flag = 1;
				break;
			case 'e': // record flag
				OSAL_trace(eRTPP, eDebug, "record flag");
				length = get_record_callid(tmp+1, &name, &tmp);
				if (length < 1) 
				{
					OSAL_trace(eRTPP, eError, "get record callid error");
					rtpp_reply_err(cookie,RTPP_ERR_RECORD_CALLID,fip,fport);
					return 0;
				}
				memset(record_callid, 0, RTPP_MAX_RECORD_CALLID);
				strncpy(record_callid, name, RTPP_MAX_RECORD_CALLID-1);
				record_callid[length] = '\0';
				e_record_flag = 1;
				tmp--;
				break;
			case 'f':
				e_complete_flags = 1;
				break;
			case 'c':

				length = get_record_callid(tmp+1, &name, &tmp);
				if (length < 1) 
				{
					OSAL_trace(eRTPP, eError, "get calleeMeidaIP error");
					rtpp_reply_err(cookie,RTPP_ERR_CALLEEMEDIA_ERROR,fip,fport);
					return 0;
				}
				strncpy(calleeMedia, name, sizeof(calleeMedia)-1);
				calleeMedia[length] = '\0';

				if(get_calleeMideaInfo(calleeMedia,length, calleeMediaIp,calleeMediaPort,calleeMediaVPort) < 0)
				{
					OSAL_trace(eRTPP, eError, "get calleeMeidaIP error");
					rtpp_reply_err(cookie,RTPP_ERR_CALLEEMEDIA_ERROR,fip,fport);
					return 0;
				}	

				e_calleeMedia_flags = 1;
				OSAL_trace(eRTPP, eDebug, "get calleeMediaIp is %s, calleeMediaPort %s, calleeMediaVport %s",calleeMediaIp,calleeMediaPort,calleeMediaVPort);
				tmp--;
				break;
			default:
				OSAL_trace(eRTPP, eError, "unknown command option '%c'",*tmp);
				break;
   		}
	}				
	if(rtpp_find_session(callid, &ss) != 0){
		OSAL_trace (eRTPP, eWarn, "command d not find ss callid:%s,from:%s,to:%s",callid,fromtag,totag);
		rtpp_reply_err(cookie,RTPP_ERR_NO_SS,fip,fport);
		return -1;
	}else{
        /* delete by liujianfeng for not used on 2016-1-19 13:32:28 */
        //#if 0
		if(e_fec_flag){
			//init fec
			if(ss->fec_inst == OSAL_NULL){
				if(fec_init(&(ss->fec_inst)) < 0){
					OSAL_trace(eRTPP, eError, "fail to init fec of directcall.");
					rtpp_free_session(ss);
					rtpp_reply_err(cookie,RTPP_ERR_INIT_FEC,fip,fport);
					return OSAL_ERROR;
				}
			}
			OSAL_trace(eRTPP, eInfo, "fec_inst is %p", ss->fec_inst);
			OSAL_trace(eRTPP, eSys,"(%d) rtpp exchange free call to direct call[%s->%s],",pMsg->msgSubId,ss->f_tag,ss->to_tag);
			ss->fec_flag = e_fec_flag;					
		}
        //#endif
        /* delete by liujianfeng end */

		//record
		if(e_record_flag){
			OSAL_trace(eRTPP, eInfo,"(%d) record call[%s->%s],",pMsg->msgSubId,ss->f_tag,ss->to_tag);
			rtpp_handle_record(RtppGlobals.record_dir, 0, record_callid, ss);
			rtpp_handle_record(RtppGlobals.record_dir, 1, record_callid, ss);
			ss->record_flag = 1;
		}

		if(e_calleeMedia_flags){
			rtpp_update_callee_mediaIP(calleeMediaIp,calleeMediaPort,ss);
		}

		//call ack
		if(!ss->finish && e_complete_flags){
			int i;
			ss->finish = e_complete_flags;
			ss->connect_time = time(NULL);
			for(i = 0; i < PORT_NUM_MAX; i++) {
				ss->left.audio[i].media_last_active = 0L;ss->left.audio[i].chc= 0;
				ss->left.video[i].media_last_active = 0L;ss->left.video[i].chc= 0;
				ss->right.audio[i].media_last_active = 0L;ss->right.audio[i].chc= 0;
				ss->right.video[i].media_last_active = 0L;ss->right.video[i].chc= 0;
			}
			rtpp_restart_media_time(ss);
		}
	
		rtpp_reply_ok(cookie,fip,fport);
	}
	return OSAL_OK;
}



char *
rtpp_strsep(char **stringp, const char *delim)
{
    char *s;
    const char *spanp;
    int c, sc;
    char *tok;

    if ((s = *stringp) == OSAL_NULL)
	return (OSAL_NULL);
    for (tok = s;;) {
	c = *s++;
	spanp = delim;
	do {
	    if ((sc = *spanp++) == c) {
		if (c == 0)
		    s = OSAL_NULL;
		else
		    s[-1] = 0;
		*stringp = s;
		return (tok);
	    }
	} while (sc != 0);
    }
    /* NOTREACHED */
}


//OSAL_INT32 handle_conference(struct sockaddr_storage *raddr, char *call_cookie, char *cookie, int argc, char *argv[], int sock)
OSAL_INT32 handle_conference(OSAL_msgHdr *pMsg)
{
	OSAL_INT32 ret = -1;
	OSAL_INT32 argc;
	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_CHAR *cookie,*op, *tmp;
	OSAL_CHAR callid[RTPP_MAX_CALLID_LEN];
	OSAL_INT32 fip;
	OSAL_UINT16 fport;
	OSAL_CHAR msgbak[512] = {0};	
	OSAL_CHAR *msg = (OSAL_CHAR  *)pMsg->pContent;
	OSAL_INT32 len = pMsg->contentLen;	

	strncpy(msgbak, msg, OSAL_strnLen(msg, 512));
	msgbak[511] = '\0';
	command_parse(msgbak,len,argv,&argc);

	if(argc < 2){
		OSAL_trace (eRTPP, eError, "err format %s",msg);
		return -1;
	}else{
		cookie = argv[0];
		op = argv[1];
	}
	
   	if(get_callid(cookie,callid) < 0){
   		OSAL_trace (eRTPP, eError, "callid failed %s",msg);
   		return -1;
   	}

	tmp = op + 1; 
	while(*tmp != '\0')
	{
		switch (*tmp) 
		{
		case 'p':
			OSAL_trace(eRTPP, eDebug, "convert p2p to conference mode");
			//ret = rtpp_convert_to_conference(call_cookie, cookie, argc, argv, local_addr, sock, raddr);
			ret = rtpp_convert_to_conference(callid, pMsg);
			if(ret<0){
				fip = pMsg->param;
				fport = pMsg->param2;
				m_cmd_repond_err (cookie, ret, *tmp, argc, argv, fip, fport);
			}
			return ret;
				
		case 'c':
			OSAL_trace(eRTPP, eDebug, "creat conference");
			//ret = rtpp_creat_conference(callid, cookie, argc, argv, local_addr, sock, raddr);
			ret = rtpp_creat_conference(callid, pMsg);
			if(ret<0){
				fip = pMsg->param;
				fport = pMsg->param2;
				m_cmd_repond_err (cookie, ret, *tmp, argc, argv, fip, fport);
			}
			return ret;

		case 'u':
			OSAL_trace(eRTPP, eDebug, "allocate port");
			//ret = rtpp_allocate_source(call_cookie, cookie, argc, argv, local_addr, sock, raddr);
			return ret;

		case 'k':
			OSAL_trace(eRTPP, eDebug, "delete port");
			//ret = rtpp_delete_source(call_cookie, cookie, sock, raddr);
			return ret;

		case 'a':
			OSAL_trace(eRTPP, eDebug, "add participant");
			//ret = rtpp_add_participant(call_cookie, cookie, argc, argv, local_addr, sock, raddr);
			ret = rtpp_add_participant(callid, pMsg);
			if(ret<0){
				fip = pMsg->param;
				fport = pMsg->param2;
				m_cmd_repond_err (cookie, ret, *tmp, argc, argv, fip, fport);
			}			
			return ret;

		case 'd':
			OSAL_trace(eRTPP, eDebug, "delete participant");
			//ret = rtpp_delete_participant(call_cookie, cookie, argc, argv, sock, raddr);
			ret = rtpp_delete_participant(callid, pMsg);
			if(ret<0){
				fip = pMsg->param;
				fport = pMsg->param2;
				m_cmd_repond_err (cookie, ret, *tmp, argc, argv, fip, fport);
			}			
			return ret;

		case 'D':
			OSAL_trace(eRTPP, eDebug, "delete conference");
			//ret = rtpp_delete_conference(call_cookie, cookie, sock, raddr);
			ret = rtpp_delete_conference(callid, cookie, pMsg);
			if(ret<0){
				fip = pMsg->param;
				fport = pMsg->param2;
				m_cmd_repond_err (cookie, ret, *tmp, argc, argv, fip, fport);
			}			
			return ret;

		case 'n':
			OSAL_trace(eRTPP, eDebug, "record pt code");
			//ret = rtpp_record_pt_code(call_cookie, cookie, argc, argv, sock, raddr);
			ret = rtpp_record_pt_code(callid, pMsg);
			if(ret<0){
				fip = pMsg->param;
				fport = pMsg->param2;
				m_cmd_repond_err (cookie, ret, *tmp, argc, argv, fip, fport);
			}			
			return ret;
			
		default:
			OSAL_trace(eRTPP, eError, "unknown conference command: %c, cookie is %s", *tmp, cookie);
			return ret;
		}
	}
	
	return ret;

}


OSAL_INT32 work_mi_rx (OSAL_msgHdr *pMsg)
{	
	OSAL_CHAR *command = (OSAL_CHAR *)pMsg->pContent;
	
	switch (*command | 32){
	  	case 'u':
			rtpp_u_proc(pMsg);
		 	break;
		case 'd':
			rtpp_d_proc(pMsg);
		 	break;
		case 'e':
			rtpp_e_proc(pMsg);
		 	break;
		case 'm':
			handle_conference(pMsg); // conferrence
		 	break;				
	  	default:
		  	OSAL_trace(eRTPP, eWarn, "invalid command[%c].",*command);
		  break;
	}
	return OSAL_OK;
}


OSAL_INT32 rtpp_notify_voice_quality(rtpp_session_t * ss, OSAL_INT32 no_media_side)
{
	OSAL_INT32 len;
	OSAL_CHAR  buf[1024];

	if(ss == OSAL_NULL)
		return OSAL_ERROR;
	
	OSAL_msgHdr mmsg;
	memset(&mmsg,0x00,sizeof(mmsg));
	len = snprintf(buf,1024,"%s:%s:%d",ss->call_id,ss->notify, no_media_side);
	mmsg.msgId = MEDIA_TIMEOUT_NOFIFY;
	mmsg.param = ss->from_ip;
	mmsg.param2 = 9988;
	mmsg.contentLen = len+1;
	mmsg.pContent = buf;
	OSAL_sendMsg(eNOTIFY,&mmsg);

	return OSAL_OK;
}

//¼ì²â¶Ë¿ÚÊÇ·ñ³¬Ê±
//0:³¬Ê±£¬
//1:Î´³¬Ê±
//-1 ²»¼ì²â£
OSAL_INT32 rtpp_check_port_timeout (port_info_t *port)
{
	OSAL_INT32 WarnValue = 5;
	OSAL_INT32 NotifyValue = 10;
	OSAL_UINT64 CurrentTime = OSAL_get_msecs();
	OSAL_INT32 NoMediaTime = 0;

	if(!port->p){
		OSAL_trace(eRTPP, eInfo, "[%d]caller:%s,callee:%s,key:%s check no assign port",port->ss->finish,port->ss->f_tag,port->ss->to_tag,port->ss->call_id);
		return -1;
	}

	NoMediaTime = (CurrentTime - port->media_last_active)/1000;
	
	port->chc++;
	if(port->media_last_active == 0L){
		OSAL_CHAR ipbuf1[20] = {0};
		inet_ntop(AF_INET,&port->fip,ipbuf1,20);
		OSAL_trace(eRTPP, eSys, "%s:%d to %s:%d %s to %s key:%s port_type:%s rtp_stream:%x state:%s chk:%d never recv media",
		ipbuf1, ntohs(port->fport), RtppGlobals.localip[port->p->index], port->p->port, 
		port->ss->f_tag,port->ss->to_tag,port->ss->call_id,porttype2str(port->va_flag),
		port->realtime_lost.last_calc_ssrc,port->ss->finish?"estabish":"connecting",port->chc);
		if(port->chc >= port->ss->timeout/MEDIA_CHECK_TIME_LEN)
			return 0;
		else return 1;
	}

	if(NoMediaTime >= WarnValue){
		OSAL_CHAR ipbuf[20] = {0};
		inet_ntop(AF_INET,&port->fip,ipbuf,20);
		OSAL_trace(eRTPP, eSys, "%s:%d to %s:%d %s to %s key:%s port_type:%s rtp_stream:%x state:%s last:%d sec no media",
		ipbuf, ntohs(port->fport), RtppGlobals.localip[port->p->index], port->p->port, 
		port->ss->f_tag,port->ss->to_tag,port->ss->call_id,porttype2str(port->va_flag),
		port->realtime_lost.last_calc_ssrc,port->ss->finish?"estabish":"connecting",NoMediaTime);
	}
	
	if(NoMediaTime >= NotifyValue && !port->no_media_notify_flag && port->ss->finish){
		rtpp_notify_voice_quality(port->ss, port->va_flag); 
		port->no_media_notify_flag = 1;
		OSAL_trace(eRTPP, eWarn, "[%d]caller:%s,callee:%s,key:%s [%s] port %d no media >= notify %d",port->ss->finish,port->ss->f_tag,port->ss->to_tag,
			port->ss->call_id,porttype2str(port->va_flag),port->p->port,NotifyValue);
	}
	
	if(NoMediaTime >= port->ss->timeout){
		OSAL_trace(eRTPP, eError, "[%d]caller:%s,callee:%s,key:%s [%s] port %d time out",port->ss->finish,port->ss->f_tag,port->ss->to_tag,port->ss->call_id,porttype2str(port->va_flag),port->p->port);
		return 0;
	}
	return 1;
}

OSAL_INT32 rtpp_check_media_timeout (rtpp_session_t * ss)
{
	OSAL_INT32 res = 0,side = 0;
	OSAL_INT32 res_left = 0,res_right = 0;
	OSAL_CHAR buf1[32] = {0}, buf2[32] = {0};
	OSAL_CHAR ipbuf1[20] = {0}, ipbuf2[20] = {0};
	OSAL_INT32 strlen = 0;
	OSAL_INT32 i;
	OSAL_INT32 left_flag = 0,right_flag = 0;

	for(i = 0; i < PORT_NUM_MAX; i++) {
		if(ss->vflag){
			rtpp_check_port_timeout(&ss->left.video[i]);
			rtpp_check_port_timeout(&ss->right.video[i]);
		}
		res = rtpp_check_port_timeout(&ss->left.audio[i]);
		if(res == 1)
			left_flag |= (0x00000001 << i);
		
		res = rtpp_check_port_timeout(&ss->right.audio[i]);
		if(res == 1)
			right_flag |=  (0x00000001 << i);
	}
	if(!ss->ttlmode && left_flag ==0 && right_flag == 0) goto notify;
	if(ss->ttlmode && ( left_flag == 0 || right_flag == 0)) goto notify;

	return OSAL_OK;
notify:
	{
		OSAL_msgHdr mmsg;
		OSAL_INT32 len;
		OSAL_CHAR  buf[1024];
		memset(&mmsg,0x00,sizeof(mmsg));
		len = snprintf(buf,1024,"%s:%s",ss->call_id,ss->notify);

		/*
		if(side == 2)
			len = snprintf(buf,1024,"%s %s %d %s %s",ss->call_id,ss->notify,side,buf1,buf2);
		else if(res_left)
			len = snprintf(buf,1024,"%s %s %d %s %s",ss->call_id,ss->notify,side,buf1," ");
		else if(res_right)
			len = snprintf(buf,1024,"%s %s %d %s %s",ss->call_id,ss->notify,side,buf2," ");
		*/	
		mmsg.msgId = MEDIA_TIMEOUT_NOFIFY;
		mmsg.param = ss->from_ip;
		mmsg.param2 = 9988;
		mmsg.contentLen = len+1;
		mmsg.pContent = buf;
		OSAL_sendMsg(eNOTIFY,&mmsg);
		ss->release_reason = 2;
		rtpp_free_session(ss);
	}
	return OSAL_OK;
}


OSAL_INT32 work_time_rx (OSAL_msgHdr *pMsg)
{
	OSAL_timerMsgHdrT *tp = (OSAL_timerMsgHdrT *)pMsg->pContent;
	OSAL_INT32 type = tp->param1;
	
	switch (type){
	  	case RTPP_TIME_MEDIA:
			rtpp_check_media_timeout((rtpp_session_t*)tp->param2);
		 	break;
	  	case RTPP_CONF_TIME_MEDIA:
			rtpp_check_conf_media_timeout((struct conference_info_t *)tp->param2);
		 	break;
	  	case RTPP_CONF_TIME_EMPTY:
			rtpp_del_empty_conf((struct conference_info_t *)tp->param2);
		 	break;	
		case Init_TestInstance_Timer:
			rtpp_init_test_instance_func();
		 	break;	
	  	default:
		  	OSAL_trace(eRTPP, eWarn, "invalid time type[%d].",type);
		  break;
	}
	return OSAL_OK;
}

OSAL_INT32 rtpp_work_main(OSAL_msgHdr *pMsg)
{	
	switch (pMsg->msgId){
		case RTPP_UDP_RTP:
		  	work_rtp_rx (pMsg);
		  	break;  
		case RTPP_UDP_MIX_RTP:
		  	//rtpp_recv_mix_media (pMsg);
		  	break;
		case RTPP_UDP_PARTY_MSG:
		  	rtpp_mixer_recv_mix_media(pMsg);
	  		break;			
		case RTPP_DISPATCH_MSG:
			work_mi_rx(pMsg);      //????RTPC????
			break;
	  	case eOsalSysMsgIdTimer:
		  	work_time_rx(pMsg);
		  	break;
	  	default:
		  	OSAL_trace(eRTPP, eWarn, "invalid msg type %d.",pMsg->msgId);
		  break;
	  }
	return OSAL_OK;	
}

OSAL_INT32 rtpp_work_end (void)
{
	return OSAL_OK;	
}


#ifdef __cplusplus
}
#endif
