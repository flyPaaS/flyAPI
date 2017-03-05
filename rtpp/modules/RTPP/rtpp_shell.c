#include "rtpp_common.h"
#include "rtpp_session.h"
#include "rtpp_main.h"
#include "rtpp_util.h" 
#include "rtpp_util.h" 
#include "rtpp_http_vm.h"

extern 	OSAL_HHASH	conferenceHashTable;

extern OSAL_CHAR ghttpVmServerIp[MAX_IP_LEN];
extern OSAL_INT32 ghttpVmServerPort;
extern OSAL_CHAR ghttpVmCfgReloaded;

static OSAL_INT32 xsh_show_config (OSAL_SHELL_ARGS)
{
	OSAL_INT32 i =0;
	
	BEGIN_OSAL_SHELL_MAP ("show RTPP module config")
	OSAL_SHELL_NO_ARG ()
	END_OSAL_SHELL_MAP ()

	{
		printf("%-30s : %s\n","Session timeout mode", RtppGlobals.ttlmode?"sider":"all");
	}

	{
		printf("%-30s : %d s\n","Media timeout", RtppGlobals.timeout);
	}

	{
		printf("%-30s : %s\n","Command socket", RtppGlobals.command_socket);
	}
	
	{
		printf("%-30s : %d\n","Host ip num", RtppGlobals.localipnum);

		for(i = 0; i < RtppGlobals.localipnum; i++){
			printf("%-30s : %s\n","Host ip" ,RtppGlobals.localip[i]);
		}
	}

	{
		printf("%-30s : %d\n","Rtpc ip num", RtppGlobals.rtpcnum);

		for(i = 0; i < RtppGlobals.rtpcnum; i++){
			printf("%-30s : %s\n","Rtpc ip" ,RtppGlobals.rtpcip[i]);
		}
	}

	printf("%-30s : %s\n", "Record dir", RtppGlobals.record_dir);
	
	printf("%-30s : %s\n", "Loss record ", RtppGlobals.rc_flag ? "on" : "off");
	printf("%-30s : %s\n", "jt flag ", RtppGlobals.jt_flag? "on" : "off");
	printf("%-30s : %d\n", "Lost history percent ", RtppGlobals.historypercent);
		
	return OSAL_OK;
}


static OSAL_INT32 xsh_show_calls_count(OSAL_SHELL_ARGS)
{
	BEGIN_OSAL_SHELL_MAP ("show RTPP calls count")
	OSAL_SHELL_NO_ARG ()
	END_OSAL_SHELL_MAP ()

	printf("%-30s: %u\n", "RTPP calls count", rtpp_hash_tbl.used);
    printf("%-30s: %d\n", "Spec calls count", 2);
	return OSAL_OK;
	
}

static OSAL_INT32 xsh_show_call_info(OSAL_SHELL_ARGS)
{
	OSAL_CHAR client[RTPP_MAX_TAG_LEN] = {0};
	OSAL_INT32 i = 0;
	rtpp_session_t *ss;
    OSAL_INT32 iSpeCall = 0;
	struct in_addr left_audio_addr,right_audio_addr,left_video_addr,right_video_addr;
	OSAL_CHAR s1[32],s2[32],s3[32],s4[32];
	
	BEGIN_OSAL_SHELL_MAP ("show RTPP call port info")
	OSAL_SHELL_STRING_ARG("clientid", &client, NULL, "client id")
	END_OSAL_SHELL_MAP ()

	{
		for(i = 0; i < RTPP_HASH_MAX_LENTH; i++){
			pthread_mutex_lock(&rtpp_hash_tbl.enter[i].lock);
			ss = rtpp_hash_tbl.enter[i].first;
			while(ss){
				if(!strcmp(ss->f_tag,client)){
					goto find;
				}
				ss = ss->next;
			}
			pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
		}
        for(i = 0; i < 2;i++){
        		ss  = &RtppGlobals.htest.ss[i];
			if(!strcmp(ss->f_tag,client)){
            			iSpeCall  = 1;
				goto find;
			}
        }
	}
	
	printf("client id %s is not find in rtpp\n",client);
	return OSAL_ERROR;
find:
	left_audio_addr.s_addr = ss->left.audio[0].fip;
	right_audio_addr.s_addr = ss->right.audio[0].fip;
	left_video_addr.s_addr = ss->left.video[0].fip;
	right_video_addr.s_addr = ss->right.video[0].fip;

	strcpy(s1,inet_ntoa(left_audio_addr));
	strcpy(s2,inet_ntoa(right_audio_addr));
	strcpy(s3,inet_ntoa(left_video_addr));
	strcpy(s4,inet_ntoa(right_video_addr));
	
	printf("client id %s quary %s fec_flag %d ok\n",client,ss->vflag?"video":"audio", ss->fec_flag);
	if(!ss->left.audio[0].p){
		printf("left audio is not alloc, pls check!!!\n");
        if(iSpeCall == 0)
		    pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
		return OSAL_ERROR;
	}
	if(!ss->right.audio[0].p){
		printf("right audio is not alloc, pls check!!!\n");
        if(iSpeCall == 0)
		    pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
		return OSAL_ERROR;
	}

	if(ss->fec_flag){
	printf("audio: [%s:%d t:%llu;a:%d fec_mode:%s llost:%.4f rlost:%.4f]%s:%d <-----> %s:%d[%s:%d t:%llu;a:%d fec_mode:%s llost:%.4f rlost:%.4f]\n",
		s1,ntohs(ss->left.audio[0].fport),ss->left.audio[0].media_last_active,ss->left.audio[0].asym,
		ss->left.audio[0].fec_mode ?  "encode" : "decode",
		ss->left.audio[0].fec_local_lost/10000.0,ss->left.audio[0].fec_peer_lost/10000.0,
		RtppGlobals.localip[ss->left.audio[0].p->index],ss->left.audio[0].p->port,
		RtppGlobals.localip[ss->right.audio[0].p->index],ss->right.audio[0].p->port,
		s2,ntohs(ss->right.audio[0].fport),ss->right.audio[0].media_last_active,ss->right.audio[0].asym,
		ss->right.audio[0].fec_mode ? "encode" : "decode",
		ss->right.audio[0].fec_local_lost/10000.0,ss->right.audio[0].fec_peer_lost/10000.0);
	}else{
		printf("audio: [%s:%d t:%llu;a:%d]%s:%d <-----> %s:%d[%s:%d t:%llu;a:%d]\n",
		s1,ntohs(ss->left.audio[0].fport),ss->left.audio[0].media_last_active,ss->left.audio[0].asym,
		RtppGlobals.localip[ss->left.audio[0].p->index],ss->left.audio[0].p->port,
		RtppGlobals.localip[ss->right.audio[0].p->index],ss->right.audio[0].p->port,
		s2,ntohs(ss->right.audio[0].fport),ss->right.audio[0].media_last_active,ss->right.audio[0].asym);
	}
	
	if(ss->vflag){
		if(!ss->left.video[0].p){
			printf("left video is not alloc, pls check!!!\n");
            if(iSpeCall == 0)
			    pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
			return OSAL_ERROR;
		}
		if(!ss->right.video[0].p){
			printf("right video is not alloc, pls check!!!\n");
            if(iSpeCall == 0)
			    pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
			return OSAL_ERROR;
		}
		printf("video: [%s:%d t:%llu;a:%d]%s:%d <-----> %s:%d[%s:%d t:%llu;a:%d]\n",
			s3,ntohs(ss->left.video[0].fport),ss->left.video[0].media_last_active,ss->left.video[0].asym,
			RtppGlobals.localip[ss->left.video[0].p->index],ss->left.video[0].p->port,
			RtppGlobals.localip[ss->right.video[0].p->index],ss->right.video[0].p->port,
			s4,ntohs(ss->right.video[0].fport),ss->right.video[0].media_last_active,ss->right.video[0].asym);
	}
    if(iSpeCall == 0)
	    pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
	return OSAL_OK;
	
}


static OSAL_INT32 xsh_set_client(rtpp_session_t *ss,OSAL_CHAR *client,OSAL_INT32 porttype,OSAL_INT32 discardInterval,OSAL_INT32 discardNumber)
{
	printf("client id %s quary %s fec_flag %d ok\n",client,ss->vflag?"video":"audio", ss->fec_flag);
	if(!ss->left.audio[0].p){
		printf("left audio is not alloc, pls check!!!\n");
		
		return OSAL_ERROR;
	}
	if(!ss->right.audio[0].p){
		printf("right audio is not alloc, pls check!!!\n");
		return OSAL_ERROR;
	}
	
	if(ss->vflag){
		if(!ss->left.video[0].p){
			printf("left video is not alloc, pls check!!!\n");
			return OSAL_ERROR;
		}
		if(!ss->right.video[0].p){
			printf("right video is not alloc, pls check!!!\n");
			return OSAL_ERROR;
		}
	}
	if(porttype == 0)
	{
		ss->left.audio[0].discardRtpInteval= discardInterval;
		ss->left.audio[0].discardNumber = discardNumber;
		ss->left.audio[0].Rtpindex= 0;
		if(ss->vflag)
		{
			ss->left.video[0].discardRtpInteval = discardInterval;
			ss->left.video[0].discardNumber = discardNumber;
			ss->left.video[0].Rtpindex = 0;
		}
	}
	else  if(porttype == 1)
	{
		ss->right.audio[0].discardRtpInteval = discardInterval;
		ss->right.audio[0].discardNumber = discardNumber;
		ss->right.audio[0].Rtpindex = 0;
		if(ss->vflag)
		{
			ss->right.video[0].discardRtpInteval = discardInterval;
			ss->right.video[0].discardNumber = discardNumber;
			ss->right.video[0].Rtpindex = 0;
		}
	}
	else
	{
		ss->left.audio[0].discardRtpInteval = discardInterval;
		ss->left.audio[0].discardNumber = discardNumber;
		ss->left.audio[0].Rtpindex = 0;

		ss->right.audio[0].discardRtpInteval = discardInterval;
		ss->right.audio[0].discardNumber = discardNumber;
		ss->right.audio[0].Rtpindex = 0;
		if(ss->vflag)
		{
			ss->left.video[0].discardRtpInteval = discardInterval;
			ss->left.video[0].discardNumber = discardNumber;
			ss->left.video[0].Rtpindex = 0;

			ss->right.video[0].discardRtpInteval = discardInterval;
			ss->right.video[0].discardNumber = discardNumber;
			ss->right.video[0].Rtpindex = 0;
		}
	}

	printf("left audio lost interval:%d, discardNumber:%d; right audio descard rtp interval:%d, discardNumber:%d\n", ss->left.audio[0].discardRtpInteval, ss->left.audio[0].discardNumber, ss->right.audio[0].discardRtpInteval,ss->right.audio[0].discardNumber);
	if(ss->vflag)
	{
		printf("left video lost interval:%d, discardNumber:%d, right video descard rtp interval:%d, discardNumber:%d\n", ss->left.video[0].discardRtpInteval, ss->left.video[0].discardNumber, ss->right.video[0].discardRtpInteval,ss->right.video[0].discardNumber);
	}
	return 0;
}


static OSAL_INT32 xsh_set_call_discardRtp(OSAL_SHELL_ARGS)
{
	OSAL_CHAR client[RTPP_MAX_TAG_LEN] = {0};
	OSAL_INT32 porttype = 0;
	OSAL_INT32 discardInterval = 0;
	OSAL_INT32 discardNumber = 0;
	OSAL_INT32 i = 0;
	rtpp_session_t *ss;
	
	BEGIN_OSAL_SHELL_MAP ("set call discard rtp rate")
	OSAL_SHELL_STRING_ARG("client", client, NULL, "client id")
	OSAL_SHELL_INT_ARG("PortType", &porttype, 0, "0:left port, 1:right prot, 2:all port")
	OSAL_SHELL_INT_ARG("DiscardInterval", &discardInterval, 0, "-2:random discard , -1 : discard all packages , 0:not discard package , x: interval rand max(x) packages discarded rand max(y) packages ")
	OSAL_SHELL_INT_ARG("DiscardNumber", &discardNumber, 0, "if random lost rate = y% , else y: discard rand max(y) packages every interval")
	END_OSAL_SHELL_MAP ()

	printf("***%s:%d:%d:%d\n",client,porttype,discardInterval,discardNumber);
	 if(porttype != 0 && porttype != 1 && porttype != 2)
	{
		printf("unknow port type\n");
		return OSAL_ERROR;
	}

	if(discardInterval < -2)
	{
		printf("descard interval should greater than -2\n");
		return OSAL_ERROR;
	}
	if(discardInterval == -2 && (100 <= discardNumber||discardNumber <= 0))
	{
		printf("random descard interval should greater than 0%% less than 100%%\n");
		return OSAL_ERROR;
	}
	if(discardNumber <= 0)
	{
		printf("descard consecutive number should greater than 0\n");
		return OSAL_ERROR;
	}

	if(discardInterval > 0 && discardNumber>5)
	{
		printf("rand discardNumber %d is not less 5\n",discardNumber);
		return OSAL_ERROR;
	}

	{
		for(i = 0; i < RTPP_HASH_MAX_LENTH; i++){
			pthread_mutex_lock(&rtpp_hash_tbl.enter[i].lock);
			ss = rtpp_hash_tbl.enter[i].first;
			while(ss){
				if(!strcmp(ss->f_tag,client)){
					xsh_set_client(ss,client,porttype,discardInterval,discardNumber);
					pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
					return OSAL_OK;
				}else if(!strcmp("all",client)){
					xsh_set_client(ss,ss->f_tag,porttype,discardInterval,discardNumber);
				}
				ss = ss->next;
			}
			pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
		}
		for(i = 0; i < 2;i++)
		{
			ss  = &RtppGlobals.htest.ss[i];
			if(!strcmp(ss->f_tag,client)){
				xsh_set_client(ss,client,porttype,discardInterval,discardNumber);
				return OSAL_OK;
			}else if(!strcmp("all",client)){
				xsh_set_client(ss,ss->f_tag,porttype,discardInterval,discardNumber);
			}
		}
		if(!strcmp("all",client)){
			printf("set all client ok in rtpp\n");
			return OSAL_OK;
		}
	}
	printf("client id %s is not find in rtpp\n",client);
	return OSAL_ERROR;
}

static OSAL_INT32 xsh_refine_command_sock(OSAL_SHELL_ARGS)
{
	OSAL_CHAR sock[RTPP_COMMAND_SOCKET_LEN] = {0};
	OSAL_INT32 ret;
	
	BEGIN_OSAL_SHELL_MAP ("Modify Host Comand sock.")
	OSAL_SHELL_STRING_ARG("NewSock", &sock, NULL, "New sock for command")
 	END_OSAL_SHELL_MAP ()
	
	strncpy(RtppGlobals.command_socket,sock,RTPP_COMMAND_SOCKET_LEN-1);

	if(RtppGlobals.controlfd > 0) {
		OSAL_async_select (eRTPP, RtppGlobals.controlfd, 0, OSAL_NULL, OSAL_NULL);
		close(RtppGlobals.controlfd);
		RtppGlobals.controlfd = -1;
	}
			
	ret = init_controlfd();
	if(ret == OSAL_ERROR) {
		printf("init control fd failed\n");
		return -1;
	}
	
	refine_cfg_entry(CONFIG_FILE, RTPP_LABEL_COMMAND, sock);
	return OSAL_OK;
}

static OSAL_INT32 xsh_switch_timeout_mode(OSAL_SHELL_ARGS)
{
	BEGIN_OSAL_SHELL_MAP ("Switch  timeout  mode status(TTL_UNIFIED or TTL_INDEPENDENT).")
	OSAL_SHELL_NO_ARG ()
	END_OSAL_SHELL_MAP()

	if(RtppGlobals.ttlmode)
	 	RtppGlobals.ttlmode = 0;
	else
		RtppGlobals.ttlmode = 1;
	
	refine_cfg_entry(CONFIG_FILE, RTPP_LABEL_TTL_MODE, int2str(RtppGlobals.ttlmode,0));
	return OSAL_OK;
}

static OSAL_INT32 xsh_change_session_timeout(OSAL_SHELL_ARGS)
{
	OSAL_INT32 timeout;
	
	BEGIN_OSAL_SHELL_MAP ("Set session timeout value(second).")
	OSAL_SHELL_INT_ARG("timeout_value", &timeout, NULL, "Session timeout value as second")
	END_OSAL_SHELL_MAP()

	if(timeout > 120 || timeout < 20){
		printf("pls input 20 ~ 120\n");
		return -1;
	}
	RtppGlobals.timeout = timeout;
	refine_cfg_entry(CONFIG_FILE, RTPP_LABEL_TIMEOUT_LEN, int2str(RtppGlobals.timeout,0));
	return OSAL_OK;
}
/*
static OSAL_INT32 xsh_modify_notify_sock(OSAL_SHELL_ARGS)
{
	OSAL_CHAR socket[256] = {0};
	OSAL_CHAR *pch;
	OSAL_INT32 i = 0;
	OSAL_INT32 ip = 0;
	OSAL_msgHdr msg = {0};
	
	BEGIN_OSAL_SHELL_MAP ("Add notify new socket for multiple CB or VPS.")
	OSAL_SHELL_STRING_ARG("NewSock", socket, NULL, "New socket for adding")
 	END_OSAL_SHELL_MAP ()

	{
		pch = strtok(socket, "/");
		while(NULL != pch) {
			if(inet_pton(AF_INET,pch,&ip) != 1){
				OSAL_trace(eRTPP, eSys,"host ip %s is invalid", pch);
				break;
			}
			strncpy(RtppGlobals.rtpcip[i],pch,15);
			RtppGlobals.rtpc[i] = ip;
			OSAL_trace(eRTPP, eSys,"local host[%d]: %s", i,RtppGlobals.localip[i]);
			i++;
			if(i == RTPP_MAX_RTPC_NUM) break;
			pch = strtok(NULL, "/");
		}
		RtppGlobals.localipnum = i;
		refine_cfg_entry(CONFIG_FILE, RTPP_LABEL_RTPC_IP, socket);
		msg.msgId = PING_RELOAD_MSG;
		OSAL_sendMsg(ePING,&msg);
	}
	return OSAL_OK;
}
*/

static OSAL_INT32 xsh_modify_notify_sock(OSAL_SHELL_ARGS)
{
	OSAL_CHAR socket[256] = {0};
	OSAL_CHAR buff_bak[256] = {0};
	OSAL_CHAR *pch;
	OSAL_INT32 i = 0;
	OSAL_INT32 ip = 0;
	OSAL_msgHdr msg = {0};
	
	BEGIN_OSAL_SHELL_MAP ("set notify socket")
	OSAL_SHELL_STRING_ARG("NewSock", socket, NULL, "New socket for setting")
 	END_OSAL_SHELL_MAP ()

	{
		strncpy(buff_bak, socket,strlen(socket));
		buff_bak[255] = '\0';
		pch = strtok(socket, "/");
		while(NULL != pch) {
			if(inet_pton(AF_INET,pch,&ip) != 1){
				OSAL_trace(eRTPP, eSys,"host ip %s is invalid", pch);
				break;
			}
			strncpy(RtppGlobals.rtpcip[i],pch,15);
			RtppGlobals.rtpc[i] = ip;
			OSAL_trace(eRTPP, eSys,"notify rtpc ip[%d]: %s", i,RtppGlobals.rtpcip[i]);
			i++;
			if(i == RTPP_MAX_RTPC_NUM) break;
			pch = strtok(NULL, "/");
		}
		RtppGlobals.rtpcnum = i;
		refine_cfg_entry(CONFIG_FILE, RTPP_LABEL_RTPC_IP, buff_bak);
		msg.msgId = PING_RELOAD_MSG;
		OSAL_sendMsg(ePING,&msg);
	}
	return OSAL_OK;
}



static OSAL_INT32
xsh_show_conferences_count(OSAL_SHELL_ARGS)
{
	int num = 0;

	BEGIN_OSAL_SHELL_MAP ("show RTPP conferences count")
	OSAL_SHELL_NO_ARG ()
	END_OSAL_SHELL_MAP ()

	num = OSAL_hashGetElemNum(conferenceHashTable);
	
	printf("%-30s: %d\n", "RTPP conferences count", num);	

	return OSAL_OK;	
}

static OSAL_INT32 xsh_set_vm_port (OSAL_SHELL_ARGS)
{		
    OSAL_INT32  t;
    OSAL_INT32  fd;
	OSAL_INT32  t_bak;
	OSAL_CHAR  cmd[128];
	
	BEGIN_OSAL_SHELL_MAP ("set vm port")
	OSAL_SHELL_INT_ARG("vm port", &t, NULL, "number such as 9999")
	END_OSAL_SHELL_MAP ()

    {
        if(t>0)
        {
            t_bak = ghttpVmServerPort;
            if(t_bak == t)
            {
                printf("vm_port %d is same\n",t);
                return OSAL_ERROR;
            }
            
        	fd = vm_create_sock(ghttpVmServerIp,t,SOCK_STREAM,IPPROTO_TCP);
            if(fd < 0)
        	{
                printf ("port %d is invalid ip %s\r\n",t, ghttpVmServerIp);
        		return -1;
            }
            
            ghttpVmServerPort = t;

            printf("set vm_port %d ok\n",t);
            //sys file
            snprintf(cmd,128,"sed -i 's/RTPP_HTTP_VM_SERVER_PORT = %d/RTPP_HTTP_VM_SERVER_PORT = %d/' %s",t_bak,t,CONFIG_FILE);
            system(cmd);
            
            ghttpVmCfgReloaded = 1;
        }else{
            printf("set vm_port %d fail\n",t);
        }
        return OSAL_OK;
    }   
}

static OSAL_INT32 xsh_set_vm_ip(OSAL_SHELL_ARGS)
{	
    OSAL_INT32 fd = 0;
	OSAL_CHAR  set_ip[MAX_IP_LEN]={0};
    OSAL_CHAR  old_ip[MAX_IP_LEN]={0};
    OSAL_CHAR  cmd[128];
		
	BEGIN_OSAL_SHELL_MAP ("set vm ip")
	OSAL_SHELL_STRING_ARG("vm ip", set_ip, NULL, "vm ip such as 192.168.1.1")
	END_OSAL_SHELL_MAP ()

    {
        if('\0' != set_ip[0])
        {
            strncpy(old_ip, ghttpVmServerIp, MAX_IP_LEN);
            if(!strcmp(old_ip, set_ip))
            {
                printf("vm_ip %s is same\n",set_ip);
                return OSAL_ERROR;
            }

        	fd = vm_create_sock(set_ip,ghttpVmServerPort,SOCK_STREAM,IPPROTO_TCP);
            if(fd < 0)
        	{
                printf ("ip %s is invalid port %d",set_ip, ghttpVmServerPort);
        		return -1;
            }
            
            strncpy(ghttpVmServerIp, set_ip, MAX_IP_LEN);

            printf("set vm_ip %s ok\n",ghttpVmServerIp);

            snprintf(cmd,128,"sed -i 's/RTPP_HTTP_VM_SERVER_IP = %s/RTPP_HTTP_VM_SERVER_IP = %s/' %s",old_ip,set_ip,CONFIG_FILE);
            system(cmd);
            ghttpVmCfgReloaded = 1;
        }else{
            printf("set vm_ip %s fail\n",ghttpVmServerIp);
        }
        return OSAL_OK;
    }
}

static OSAL_INT32 xsh_up_speccall(OSAL_SHELL_ARGS)
{
    OSAL_INT32 iFec = 0;
	OSAL_INT32 iModel = 0;
    OSAL_CHAR  remote_ip[MAX_IP_LEN]={0};
    OSAL_INT32 remote_port = 0;
       
	BEGIN_OSAL_SHELL_MAP ("show RTPP call port info")
     OSAL_SHELL_INT_ARG("set fec", &iFec, 0, "0:no fec; 1:use fec")
	OSAL_SHELL_INT_ARG("set retpp model", &iModel, 0, "0:Encode-Decode; 1:Decode-Encode")
	OSAL_SHELL_STRING_ARG("remote ip", &remote_ip, NULL, "remote rtpp ip")
	OSAL_SHELL_INT_ARG("remote port", &remote_port, 0, "remote rtpp port")
	END_OSAL_SHELL_MAP ()

    if(iFec != 0&&iFec != 1)
    {
    	printf("rtpp iFec suport 0 or 1\n");
        return OSAL_ERROR;
    }
    if(iModel != 0&&iModel != 1&&iModel != 2)
	{
    	printf("rtpp model suport 0 or 1\n");
        return OSAL_ERROR;
    }
    if( rtpp_us_proc (iFec,iModel,remote_ip,remote_port) < 0)
    {
    	return OSAL_ERROR;
    }
	return OSAL_OK;	
}

static OSAL_INT32 xsh_Show_speccall(OSAL_SHELL_ARGS)
{
	OSAL_CHAR client[RTPP_MAX_TAG_LEN] = {0};
       OSAL_CHAR lfecModel[RTPP_MAX_TAG_LEN] = {0};
       OSAL_CHAR rfecModel[RTPP_MAX_TAG_LEN] = {0};
	rtpp_session_t *ss;
       OSAL_INT32 iFec = 0;
	struct in_addr left_audio_addr,right_audio_addr,left_video_addr,right_video_addr;
	OSAL_CHAR s1[32],s2[32],s3[32],s4[32];

       BEGIN_OSAL_SHELL_MAP ("show RTPP call port info")
       OSAL_SHELL_INT_ARG("set fec", &iFec, 0, "0:no fec; 1:fec")
	END_OSAL_SHELL_MAP ()
	
       ss  = &RtppGlobals.htest.ss[iFec];
       left_audio_addr.s_addr = ss->left.audio[0].fip;
	right_audio_addr.s_addr = ss->right.audio[0].fip;
	left_video_addr.s_addr = ss->left.video[0].fip;
	right_video_addr.s_addr = ss->right.video[0].fip;

	strcpy(s1,inet_ntoa(left_audio_addr));
	strcpy(s2,inet_ntoa(right_audio_addr));
	strcpy(s3,inet_ntoa(left_video_addr));
	strcpy(s4,inet_ntoa(right_video_addr));
	
	printf("client id %s quary %s fec_flag %d ok\n",client,ss->vflag?"video":"audio", ss->fec_flag);
	if(!ss->left.audio[0].p){
		printf("left audio is not alloc, pls check!!!\n");
		return OSAL_ERROR;
	}
	if(!ss->right.audio[0].p){
		printf("right audio is not alloc, pls check!!!\n");
		return OSAL_ERROR;
	}

       if(ss->left.audio[0].fec_mode == 0)
        {
            memcpy(lfecModel,"decode",strlen("decode"));
       }
       else if(ss->left.audio[0].fec_mode == 1)
        {
             memcpy(lfecModel,"encode",strlen("encode"));
       }
        else
        {
             memcpy(lfecModel,"null",strlen("null"));
        }

        if(ss->right.audio[0].fec_mode == 0)
        {
            memcpy(rfecModel,"decode",strlen("decode"));
       }
       else if(ss->right.audio[0].fec_mode == 1)
       {
             memcpy(rfecModel,"encode",strlen("encode"));
       }
        else
        {
             memcpy(rfecModel,"null",strlen("null"));
        }
	printf("audio: [%s:%d t:%llu;a:%d fec_mode:%s]%s:%d <-----> %s:%d[%s:%d t:%llu;a:%d fec_mode:%s]\n",
		s1,ntohs(ss->left.audio[0].fport),ss->left.audio[0].media_last_active,ss->left.audio[0].asym,
		lfecModel,
		RtppGlobals.localip[ss->left.audio[0].p->index],ss->left.audio[0].p->port,
		RtppGlobals.localip[ss->right.audio[0].p->index],ss->right.audio[0].p->port,
		s2,ntohs(ss->right.audio[0].fport),ss->right.audio[0].media_last_active,ss->right.audio[0].asym,
		rfecModel);
	printf("package count:left:[rcv:%d snd:%d],right:[rcv:%d,snd:%d]\n",ss->left.audio[0].recv_packets,ss->left.audio[0].send_packets,ss->right.audio[0].recv_packets,ss->right.audio[0].send_packets);
	return OSAL_OK;
}

static OSAL_INT32 xsh_rtpp_loss_rc_mode(OSAL_SHELL_ARGS)
{
	OSAL_CHAR on_off = 0;
	/*ÎÒ*/
	BEGIN_OSAL_SHELL_MAP ("rtpp do recording by loss_rate")
	OSAL_SHELL_INT_ARG("set loss record mode", &on_off, NULL, "0:off,1:on ")
	END_OSAL_SHELL_MAP ();
	if(on_off != 0 && on_off != 1){
    	printf("please input 0 or 1\n");
        return OSAL_ERROR;
    }

    rtpp_set_rc_flag(on_off);
    refine_cfg_entry(CONFIG_FILE, RTPP_LABEL_LOSS_RC_MODE, int2str(on_off,0));
    
	return OSAL_OK;
}

static OSAL_INT32 xsh_rtpp_jt_flag(OSAL_SHELL_ARGS)
{
	OSAL_CHAR on_off = 0;
	
	BEGIN_OSAL_SHELL_MAP ("set rtpp jt calc")
	OSAL_SHELL_INT_ARG("jt mode", &on_off, NULL, "0:off,1:on ")
	END_OSAL_SHELL_MAP ();
	if(on_off != 0 && on_off != 1){
    	printf("please input 0 or 1\n");
        return OSAL_ERROR;
    }

    RtppGlobals.jt_flag= on_off;
    refine_cfg_entry(CONFIG_FILE, RTPP_LABEL_JT_FLAG, int2str(on_off,0));
    
	return OSAL_OK;
}


static OSAL_INT32 xsh_rtpp_set_history_percent(OSAL_SHELL_ARGS)
{
	OSAL_INT32 history = 0;
	
	BEGIN_OSAL_SHELL_MAP ("set history percent for lost")
	OSAL_SHELL_INT_ARG("percent", &history, NULL, "percent is 0 ~ 100")
	END_OSAL_SHELL_MAP ();
	if(history >= 0 && history <= 100){
		RtppGlobals.historypercent = history;
		return OSAL_OK;
    }
	printf("please input 0 ~ 100\n");
    return OSAL_ERROR;
}


void rtpp_init_shell ()
{
	OsalSNode parent;

	parent = osal_register_snode (NULL, "RTPP", NULL, 0);
	osal_register_snode (parent, "ShowConfig", xsh_show_config, 0);
	osal_register_snode (parent, "ShowCallsCount", xsh_show_calls_count, 0);
	osal_register_snode (parent, "ShowCallInfo", xsh_show_call_info, 0);
	osal_register_snode (parent, "SetCommandSock ", xsh_refine_command_sock, 0);
	osal_register_snode (parent, "SwitchTimeoutMode", xsh_switch_timeout_mode, 0);
	osal_register_snode (parent, "SetSessionTimeout", xsh_change_session_timeout, 0);
	osal_register_snode (parent, "setNotifySock", xsh_modify_notify_sock, 0);
	osal_register_snode (parent, "ShowConferencesCount", xsh_show_conferences_count, 0);
    osal_register_snode (parent, "SetVmIp", xsh_set_vm_ip, 0);
    osal_register_snode (parent, "SetVmPort", xsh_set_vm_port, 0);
    osal_register_snode (parent, "SetDiscardRtp", xsh_set_call_discardRtp, 0);
    osal_register_snode (parent, "UpdateSpecialCall", xsh_up_speccall, 0);
    osal_register_snode (parent, "ShowSpecialCall", xsh_Show_speccall, 0);
    osal_register_snode (parent, "SetLossRecord", xsh_rtpp_loss_rc_mode, 0);
	osal_register_snode (parent, "SetJitterCalc", xsh_rtpp_jt_flag, 0);
	osal_register_snode (parent, "SetHistoryPercent", xsh_rtpp_set_history_percent, 0);
}

