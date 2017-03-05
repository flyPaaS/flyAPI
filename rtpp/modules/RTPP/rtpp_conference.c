#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/types.h> 
#include <arpa/inet.h>
#include "OSAL_trace.h"
#include "OSAL_hash.h"
#include "OSAL_memory.h"
#include "OSAL_mi.h"
#include "common.h"
#include "rtpp_conference.h"
#include "rtpp_main.h"

extern RtppGlobalsT RtppGlobals;
extern 	OSAL_HHASH	conferenceHashTable;
extern pthread_mutex_t rtpp_conf_hashtable_lock;


static void init_rtpp_conf_session (struct conference_info_t *conf)
{	
	int i;
	struct sockaddr_in ia;
	struct participant_info_t *sp;

	if(!conf)
		return;


	memset(&ia, 0, sizeof(ia));
    ia.sin_family      = AF_INET;
    ia.sin_port        = htons(0);
    ia.sin_addr.s_addr = inet_addr("127.0.0.1");
	
	for (i = 0; i < MAX_PARTICIPANT_NUM;i++) {
		sp = &conf->participant[i];
		sp->index = i;
		sp->valid = 0;
		sp->id = -2;
		sp->next_free = i + 1;
		memcpy(&sp->addr[0], (struct sockaddr *)&ia, sizeof(ia));
		memcpy(&sp->addr[1], (struct sockaddr *)&ia, sizeof(ia));		
	}

/*
	conf->participant[0].next_free = 0;
	conf->participant[MAX_PARTICIPANT_NUM-1].next_free = 0;
	conf->session_free_list = 1;
*/
	conf->session_free_list = 0;
	conf->session_active = 0;
	conf->has_added = 0;
	conf->check_conf_media_timer = OSAL_INVALID_TIMER_ID;
	conf->empty_conftimer = OSAL_INVALID_TIMER_ID;
	pthread_mutex_init(&conf->conflock, NULL); 	

}


static void init_rtpp_conf_session_entry(struct participant_info_t *sp)
{
	if(!sp)
		return;
	sp->valid = 1;	
	sp->mixed = 0;
	sp->id = -2;
	sp->packetsSent = 0;
	sp->packetsReceived = 0;
	sp->ttl = RtppGlobals.timeout;
}

struct participant_info_t * 
get_rtpp_conf_session (struct conference_info_t *conf)
{
	int idx;
	struct participant_info_t *sp = NULL;

	if(!conf)
		return NULL;
	idx = conf->session_free_list;

	if (idx < 0 || idx >= MAX_PARTICIPANT_NUM) {
		OSAL_trace(eRTPP, eError, "allocate session index:%d err.", idx);
		return NULL;
	}

	sp = &conf->participant[idx];
	init_rtpp_conf_session_entry(sp);
	conf->session_free_list = sp->next_free;
	conf->session_active++;
	conf->has_added = 1;;

	return sp;
	
}

void put_rtpp_conf_session(struct conference_info_t *conf, struct participant_info_t *sp)
{
	int idx;
	if (!sp || !conf)
		return;
	idx = sp->index;
	memset(sp, 0, sizeof(struct participant_info_t));
	sp->index = idx;	
	sp->id = -2;
	sp->next_free = conf->session_free_list;
	conf->session_free_list = sp->index;
	conf->session_active--;	
}



/*
int poll_append_conf_session(struct conference_info_t *sp, int pid, int index)
{
	if(!sp)
		return OSAL_ERROR;
	
	if (sp->participant[pid].fd[index] != -1) {
		if (OSAL_OK != OSAL_async_select (eRTPP, sp->participant[pid].fd[index], RTPP_UDP_PARTY_MSG, OSAL_NULL, sp)) {
			  OSAL_trace (eRTPP, eError, "select udp party msgSocket failed.");
			  return OSAL_ERROR;
		}
	}

	return OSAL_OK;
}


void poll_remove_conf_session(struct conference_info_t *sp, int pid, int index)
{
	if(!sp)
		return;
	if (sp->participant[pid].fd[index] != -1) {
		if (OSAL_OK != OSAL_async_select (eRTPP, sp->participant[pid].fd[index] , 0, OSAL_NULL, OSAL_NULL)) 
			  OSAL_trace (eRTPP, eError, "select udp party msgSocket failed.");
	}
}


static void
m_cmd_repond(struct cfg *cf, int fd,
struct sockaddr_storage *raddr, socklen_t rlen, char *cookie, char *content)
{
    int len;
    char buf[1024];

    len = 0;
    if (cookie != OSAL_NULL && content != OSAL_NULL) 
	{
		len = sprintf(buf, "%s %s\n", cookie, content);
    }	
	OSAL_trace(eRTPP, eInfo, "mc_cmd_repond: buf len is %d, buf is %s",len, buf);
	
    doreply(cf, fd, buf, len, raddr, rlen);
}

void
m_cmd_repond_err(struct cfg *cf, int fd,
struct sockaddr_storage *raddr, socklen_t rlen, char *cookie, char *cmd, int argc, char *argv[])
{
    int i, len;
    char buf[256];

    len = 0;
	int code = -1;
    if (cookie != OSAL_NULL) 
	{
		//len = sprintf(buf, "%s %s %d\n", cookie, cmd, code);
		len = sprintf(buf, "%s %s %d", cookie, cmd, code);
    }
	for(i=1;i<argc;i++){
		strcat(buf, " ");
		strcat(buf, argv[i]);
		len += strlen(argv[i]) + 1;
	}
	strcat(buf, "\n");
	len += 1;
	
	OSAL_trace(eRTPP, eInfo, "mc_cmd_repond: buf len is %d, buf is %s",len, buf);
	
    doreply(cf, fd, buf, len, raddr, rlen);
}
*/

OSAL_INT32 m_cmd_repond_err (OSAL_CHAR *cookie,OSAL_INT32 errcode, OSAL_CHAR cmd, int argc, char *argv[], OSAL_INT32 ipvalue,OSAL_UINT16 port)
{
    int i, len;
    char buf[256];

    len = 0;
	int code = -1;
    if (cookie != OSAL_NULL) 
	{
		len = sprintf(buf, "%s %c %d", cookie, cmd, code);
    }
	for(i=1;i<argc;i++){
		strcat(buf, " ");
		strcat(buf, argv[i]);
		len += strlen(argv[i]) + 1;
	}
	strcat(buf, "\n");
	len += 1;
	
	OSAL_trace(eRTPP, eInfo, "mc_cmd_repond: buf len is %d, buf is %s",len, buf);

	rtpp_udp_trans(RtppGlobals.controlfd, buf, len, ipvalue, port);

	return 0;
}

OSAL_INT32 m_cmd_repond (OSAL_CHAR *cookie, char *content,OSAL_INT32 ipvalue,OSAL_UINT16 port)
{
    int len;
    char buf[1024];

    len = 0;
    if (cookie != OSAL_NULL && content != OSAL_NULL) 
	{
		len = sprintf(buf, "%s %s\n", cookie, content);
    }	
	OSAL_trace(eRTPP, eInfo, "mc_cmd_repond: buf len is %d, buf is %s",len, buf);

	
	rtpp_udp_trans(RtppGlobals.controlfd, buf, len, ipvalue, port);

	return 0;
}



OSAL_INT32 get_pt_values(OSAL_CHAR *buf,OSAL_INT32 len,OSAL_CHAR *argv[],OSAL_INT32 *argc)
{
	OSAL_INT32 i;
	OSAL_INT32 para_num = 1;

	argv[0] = buf;
	
	for(i = 0; i < len; i++){
		if(',' == buf[i]){
			argv[para_num++] = buf + i + 1;
			buf[i] = 0;
		}
	}
	*argc = para_num;
	return 0;
} 


OSAL_INT32 rtpp_mixer_selct_alloc_port(OSAL_INT32 mod_id,OSAL_CHAR index, struct participant_info_t *port_info)
{
	alloc_info_t *alloc;
	
	alloc = rtpp_alloc_port(index);
	if(NULL == alloc){
		OSAL_trace(eRTPP, eError,"IP %d is alloc failed", index);
		return -1;
	}
	alloc->next = 0;

	if (OSAL_OK != OSAL_async_select (mod_id, alloc->fd, RTPP_UDP_PARTY_MSG, OSAL_NULL, port_info)){
		OSAL_trace (eRTPP, eError, "select party rtp failed.");
		rtpp_free_port(alloc);
		return -1;
	}
	
	if (OSAL_OK != OSAL_async_select (mod_id, alloc->rtcpfd, RTPP_UDP_PARTY_MSG, OSAL_NULL, port_info)){
		OSAL_trace (eRTPP, eError, "select party rtcp failed.");
		OSAL_async_select (mod_id, alloc->fd, 0, OSAL_NULL, 0);
		rtpp_free_port(alloc);
		return -1;
	}	

	port_info->p = alloc;
			
	return 0;
}

OSAL_INT32 rtpp_mixer_disselct_free_port(OSAL_INT32 mod_id,alloc_info_t *dealloc)
{

	if (OSAL_OK != OSAL_async_select (mod_id, dealloc->fd, 0, OSAL_NULL, 0)){
		OSAL_trace (eRTPP, eError, "remove %d poll rtp failed.", dealloc->fd);
		return -1;
	}
	
	if (OSAL_OK != OSAL_async_select (mod_id, dealloc->rtcpfd, 0, OSAL_NULL, 0)){
		OSAL_trace (eRTPP, eError, "remove %d poll rtcp failed.", dealloc->rtcpfd);
		return -1;
	}
	
	rtpp_free_port(dealloc);
			
	return 0;
}


OSAL_INT32 rtpp_mixer_selct_port(OSAL_INT32 mod_id, struct participant_info_t *port_info)
{
	if(!port_info)
		return -1;
	
	if (OSAL_OK != OSAL_async_select (mod_id, port_info->p->fd, RTPP_UDP_PARTY_MSG, OSAL_NULL, port_info)){
		OSAL_trace (eRTPP, eError, "select party rtp failed.");
		rtpp_free_port(port_info->p);
		return -1;
	}
	
	if (OSAL_OK != OSAL_async_select (mod_id, port_info->p->rtcpfd, RTPP_UDP_PARTY_MSG, OSAL_NULL, port_info)){
		OSAL_trace (eRTPP, eError, "select party rtcp failed.");
		OSAL_async_select (mod_id, port_info->p->fd, 0, OSAL_NULL, 0);
		rtpp_free_port(port_info->p);
		return -1;
	}	
			
	return 0;
}


/*
void check_conference_exsited_time(OSAL_HHASH hHash, void  *elem, void *param)
{
	int		i;
	int		offset = 0;
	time_t	t = time(NULL);
	char	keyBuff[MAX_COOKIE_LEN];
	struct  conference_info_t *party = NULL;
	if(NULL == elem)
    {
    	return;
    }

	party = (struct conference_info_t *)elem;

	offset = t - party->ttl;
	if(offset > 9000) //2.5 hours
	{
		OSAL_trace(eRTPP,  eSys,"[Check conference] conference :%s exists too long time(%d s), delete the conference now.",party->call_cookie, offset);
		memset(keyBuff, 0, sizeof(keyBuff));				
		strncpy(keyBuff, party->call_cookie, strlen(party->call_cookie));
		keyBuff[MAX_COOKIE_LEN-1] = '\0';

		if(Mixer_delete_conference(party->inst) < 0){
			OSAL_trace(eRTPP, eError, "fail to remove mixer conference");
		}

		for(i=0;i<MAX_PARTICIPANT_NUM;i++)
		{
			if(party->participant[i].valid){
				OSAL_trace(eRTPP, eDebug, "delete participant %s", party->participant[i].uid);
				poll_remove_conf_session(party, i, 0);
				poll_remove_conf_session(party, i, 1);
				close(party->participant[i].fd[0]);
				close(party->participant[i].fd[1]);
				put_rtpp_conf_session(party, &party->participant[i]);			
			}
		}
		if (party->timeout_data.notify_tag != OSAL_NULL) {
			free(party->timeout_data.notify_tag);
			party->timeout_data.notify_tag = OSAL_NULL;
		}		
		OSAL_hashElemDelete(conferenceHashTable, keyBuff, party);		
	}

}


void rtpp_check_conferrence_time(void)
{
	OSAL_hashDoAll(conferenceHashTable, check_conference_exsited_time, NULL);
}


int rtpp_conf_notify_schedule(struct conference_info_t *party, int pid, int flag)
{
	if(!party)
		return -1;
	
    struct rtpp_notify_wi *wi;
    struct rtpp_timeout_handler *th = party->timeout_data.handler;
    int len;
    char *notify_buf;
	char notify_str[512] = {0};

    if (th == OSAL_NULL) {
		OSAL_trace(eRTPP, eError, "session timeout handle NULL.");
      	      return 0;
    }
	
    wi = rtpp_notify_queue_get_free_item(th->socket_name);

    if (wi == OSAL_NULL)
        return -1;
	
	wi->th = th;

	if(flag)
		len = sprintf(notify_str, "M%s.0 %c %s %s\n", party->call_cookie, 't',
			party->timeout_data.notify_tag, party->participant[pid].partid_uid);
	else
		len = sprintf(notify_str, "M%s.0 %c %s\n", party->call_cookie, 't', party->timeout_data.notify_tag);

	len += 2;
    if (wi->notify_buf == OSAL_NULL) {
        wi->notify_buf = (char*)malloc(len);
        if (wi->notify_buf == OSAL_NULL) {
	            rtpp_notify_queue_return_free_item(wi);
	            return -1;
        }
    } 
    else {
        notify_buf = (char *)realloc(wi->notify_buf, len);
        if (notify_buf == OSAL_NULL) 
		{
            rtpp_notify_queue_return_free_item(wi);
            return -1;
        }
        wi->notify_buf = notify_buf;
    }
    wi->len = len;

    if(wi->notify_buf) 
        len = snprintf(wi->notify_buf, len, "%s\n", notify_str);

    rtpp_notify_queue_put_item(wi);
    return 0;
}


void *check_conference_ttl(OSAL_HHASH hHash, void  *elem, void *param)
{
	int		i;
	char	keyBuff[MAX_COOKIE_LEN];
	struct  conference_info_t *party = NULL;
	if(NULL == elem)
    {
    	return param;
    }

	party = (struct conference_info_t *)elem;

	//if active session is zero, delete the conference.
	if((party->has_added == 1) && (party->session_active == 0))
	{
		rtpp_conf_notify_schedule(party, i, 0);
		OSAL_trace(eRTPP, eInfo, "when the active session is zero, delete the conference");
		
		memset(keyBuff, 0, sizeof(keyBuff));				
		strncpy(keyBuff, party->call_cookie, strlen(party->call_cookie));
		keyBuff[MAX_COOKIE_LEN-1] = '\0';		
		if(Mixer_delete_conference(party->inst) < 0){
			OSAL_trace(eRTPP, eError, "fail to remove mixer conference");
			return NULL;
		}
		if (party->timeout_data.notify_tag != OSAL_NULL) {
			free(party->timeout_data.notify_tag);
			party->timeout_data.notify_tag = OSAL_NULL;
		}	
		OSAL_hashElemDelete(conferenceHashTable, keyBuff, party);	
	}

	//if participant ttl is zero, notify to rtpc.
	for(i=0;i<MAX_PARTICIPANT_NUM;i++)
	{
		OSAL_trace(eRTPP, eDebug, "wty debug, loop %d", i);
		if(party->participant[i].mixed){
			OSAL_trace(eRTPP, eDebug, "wty debug 1, loop %d", i);
			if(party->participant[i].ttl == 0) {
				OSAL_trace(eRTPP, eDebug, "wty debug 2, loop %d", i);
				OSAL_trace(eRTPP, eWarn, "participant %s media timeout", party->participant[i].uid);
				rtpp_conf_notify_schedule(party, i, 1);
				OSAL_trace(eRTPP, eDebug, "wty debug 3, loop %d", i);
				if(party->participant[i].id > -1){
					OSAL_trace(eRTPP, eDebug, "wty debug 4, loop %d", i);
					if(Mixer_remove_participant(party->inst, party->participant[i].id) < 0){ 						
						OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
						return NULL;
					}
					OSAL_trace(eRTPP, eDebug, "wty debug 5, loop %d", i);
				}
				OSAL_trace(eRTPP, eDebug, "wty debug 6, loop %d", i);
				poll_remove_conf_session(party, i, 0);
				poll_remove_conf_session(party, i, 1);
				close(party->participant[i].fd[0]);
				close(party->participant[i].fd[1]);
				OSAL_trace(eRTPP, eDebug, "wty debug 7, loop %d", i);
				put_rtpp_conf_session(party, &party->participant[i]);
				OSAL_trace(eRTPP, eDebug, "wty debug 8, loop %d", i);
			}
			else {
			
				if (party->participant[i].ttl != 0) {
					if(party->participant[i].mixed == 1 && party->participant[i].ttl%5 == 0 && party->participant[i].ttl!=RtppGlobals.cfg.max_ttl)
						OSAL_trace(eRTPP, eWarn, "%s %d's no media", party->participant[i].uid, RtppGlobals.cfg.max_ttl-party->participant[i].ttl);			
					party->participant[i].ttl--;
				}
			}		
		}
	}

	return NULL;
}
*/


OSAL_INT32 rtpp_start_conf_empty_time (struct conference_info_t *conf)
{
	OSAL_timerMsgHdrT t;

	memset(&t,0,sizeof(t));

	t.moduleId = conf->mod_id;
	t.param1 = RTPP_CONF_TIME_EMPTY;
	t.param2 = conf;
	OSAL_trace(eRTPP, eInfo, "start empty conf timer");
#ifdef USE_SYN_TIMER	
	conf->empty_conftimer = OSAL_stimerUseOneTime(&t, 10*60*1000);  // 10 minute
#else
	conf->empty_conftimer = OSAL_timerUseOneTime(&t, 10*60*1000);	// 10 minute
#endif
	return 0;
}



OSAL_INT32 rtpp_stop_conf_empty_time (struct conference_info_t *conf)
{
	if(!conf)
		return OSAL_ERROR;
	
	if(conf->empty_conftimer != OSAL_INVALID_TIMER_ID){
		OSAL_trace(eRTPP, eInfo, "delete empty conf timer");
		OSAL_stimerStop(conf->empty_conftimer);
		conf->empty_conftimer = OSAL_INVALID_TIMER_ID;
	}

	
	return 0;
}



OSAL_INT32 rtpp_del_empty_conf (struct conference_info_t * ss)
{
	OSAL_INT32 i, j, len;
	OSAL_INT32 from_ip, module_id;
	OSAL_CHAR  buf[1024];
	char keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *party = NULL;

	if(ss == OSAL_NULL)
		return OSAL_ERROR;

	party = ss;

	OSAL_trace(eRTPP, eInfo, "when the active session is zero for 10 minutes, delete the conference, cookie is %s", party->call_cookie);
	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, party->call_cookie, strlen(party->call_cookie));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';		
	if(Mixer_delete_conference(party->inst) < 0){
		OSAL_trace(eRTPP, eError, "fail to remove mixer conference");
		return OSAL_ERROR;
	}

	if(party->check_conf_media_timer){
		OSAL_trace(eRTPP, eInfo, "delete conf timer");
		OSAL_stimerStop(party->check_conf_media_timer);
	}
	
	for(j=0;j<MAX_PARTICIPANT_NUM;j++)
	{
		if(party->participant[j].valid){
			OSAL_trace(eRTPP, eInfo, "delete participant %s", party->participant[j].uid);
			rtpp_mixer_disselct_free_port(module_id,party->participant[j].p);
			put_rtpp_conf_session(party, &party->participant[j]);			
		}
	}
	
	from_ip = party->from_ip;
	len = snprintf(buf, 1024, "M%s.0 %c %s\n", party->call_cookie, 't', party->notify);	
	pthread_mutex_lock(&rtpp_conf_hashtable_lock);			
	OSAL_hashElemDelete(conferenceHashTable, keyBuff, party);
	pthread_mutex_unlock(&rtpp_conf_hashtable_lock);

	return OSAL_OK;
}



OSAL_INT32 rtpp_start_conf_media_time (struct conference_info_t *conf)
{
	OSAL_timerMsgHdrT t;

	memset(&t,0,sizeof(t));

	t.moduleId = conf->mod_id;
	t.param1 = RTPP_CONF_TIME_MEDIA;
	t.param2 = conf;
	//conf->check_conf_media_timer = OSAL_stimerStart(&t,MEDIA_CHECK_TIME_LEN*1000);
	conf->check_conf_media_timer = OSAL_stimerStart(&t, 1000);
	return 0;
}



OSAL_INT32 rtpp_check_conf_media_timeout (struct conference_info_t * ss)
{
	OSAL_INT32 i, j, len;
	OSAL_INT32 from_ip, module_id;
	OSAL_CHAR  buf[1024];
	char keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *party = NULL;

	if(ss == OSAL_NULL)
		return OSAL_ERROR;

	party = ss;


	if((party->session_active == 0) && (party->empty_conftimer == OSAL_INVALID_TIMER_ID)){
		rtpp_start_conf_empty_time(party);
	}
	else if((party->session_active > 0) && (party->empty_conftimer != OSAL_INVALID_TIMER_ID)){
		rtpp_stop_conf_empty_time(party);
	}
	

/*
	//if active session is zero, delete the conference.	
	if((party->has_added == 1) && (party->session_active == 0))
	{
		OSAL_trace(eRTPP, eInfo, "when the active session is zero, delete the conference, cookie is %s", party->call_cookie);
		memset(keyBuff, 0, sizeof(keyBuff));				
		strncpy(keyBuff, party->call_cookie, strlen(party->call_cookie));
		keyBuff[MAX_COOKIE_LEN-1] = '\0';		
		if(Mixer_delete_conference(party->inst) < 0){
			OSAL_trace(eRTPP, eError, "fail to remove mixer conference");
			return OSAL_ERROR;
		}

		if(party->check_conf_media_timer){
			OSAL_trace(eRTPP, eInfo, "delete conf timer");
			OSAL_stimerStop(party->check_conf_media_timer);
		}
		
		for(j=0;j<MAX_PARTICIPANT_NUM;j++)
		{
			if(party->participant[j].valid){
				OSAL_trace(eRTPP, eInfo, "delete participant %s", party->participant[j].uid);
				rtpp_mixer_disselct_free_port(module_id,party->participant[j].p);
				put_rtpp_conf_session(party, &party->participant[j]);			
			}
		}
		
		from_ip = party->from_ip;
		len = snprintf(buf, 1024, "M%s.0 %c %s\n", party->call_cookie, 't', party->notify);	
		pthread_mutex_lock(&rtpp_conf_hashtable_lock);			
		OSAL_hashElemDelete(conferenceHashTable, keyBuff, party);
		pthread_mutex_unlock(&rtpp_conf_hashtable_lock);
		
		goto notify;
	}
*/

	//if participant ttl is zero, notify to rtpc.
	for(i=0;i<MAX_PARTICIPANT_NUM;i++)
	{
		//OSAL_trace(eRTPP, eDebug, "wty debug, loop %d", i);
		if(party->participant[i].mixed){
			//OSAL_trace(eRTPP, eDebug, "wty debug 1, loop %d", i);
			if(party->participant[i].ttl == 0) {
				//OSAL_trace(eRTPP, eDebug, "wty debug 2, loop %d", i);
				OSAL_trace(eRTPP, eWarn, "participant %s media timeout, cookie is %s", party->participant[i].uid, party->call_cookie);
				//OSAL_trace(eRTPP, eDebug, "wty debug 3, loop %d", i);
				if(party->participant[i].id > -1){
					//OSAL_trace(eRTPP, eDebug, "wty debug 4, loop %d", i);
					if(Mixer_remove_participant(party->inst, party->participant[i].id) < 0){ 						
						OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
						return OSAL_ERROR;
					}
					//OSAL_trace(eRTPP, eDebug, "wty debug 5, loop %d", i);
				}
				len = snprintf(buf, 1024, "M%s.0 %c %s %s\n", party->call_cookie, 't', party->notify, party->participant[i].partid_uid);				
				//OSAL_trace(eRTPP, eDebug, "wty debug 6, loop %d", i);

				module_id = party->mod_id;
				from_ip = party->from_ip;
				rtpp_mixer_disselct_free_port(module_id,party->participant[i].p);
				
				//OSAL_trace(eRTPP, eDebug, "wty debug 7, loop %d", i);
				put_rtpp_conf_session(party, &party->participant[i]);
				//OSAL_trace(eRTPP, eDebug, "wty debug 8, loop %d", i);
				goto notify;
			}
			else {		
				if (party->participant[i].ttl != 0) {
					if(party->participant[i].mixed == 1 && party->participant[i].ttl%5 == 0 && party->participant[i].ttl!=RtppGlobals.timeout)
						OSAL_trace(eRTPP, eWarn, "%s %d's no media", party->participant[i].uid, RtppGlobals.timeout - party->participant[i].ttl);			
					party->participant[i].ttl--;
				}
			}		
		}
	}
	
	return OSAL_OK;
	
notify:
	{
		OSAL_msgHdr mmsg;
		memset(&mmsg,0x00,sizeof(mmsg));
		mmsg.msgId = MEDIA_TIMEOUT_NOFIFY;
		mmsg.param = from_ip;
		mmsg.param2 = 9988;
		mmsg.contentLen = len+1;
		mmsg.pContent = buf;
		OSAL_sendMsg(eNOTIFY,&mmsg);
	}
	return OSAL_OK;
}




void rtpp_mixer_trace_log_cb(int level, const char* logbuf, int loglen)
{
	OSAL_trace(eRTPP, eDebug,"#TRACE:Level=%d, %.*s\n", level, loglen, logbuf);
}


int rtpp_mixer_send_media_cb(void* us_handle, int m_cnid, const media_data_t* m_data)
{
	int i;
	int s_fd = -1;
	int send_len = -1;
	struct conference_info_t *party;
	struct sockaddr saddr;
	struct sockaddr_in *s_in; 
	socklen_t saddrlen = sizeof(saddr);

	if (!m_data || !us_handle)
		return send_len;

	party = (struct conference_info_t *)us_handle;

	pthread_mutex_lock(&party->conflock);
	if(party){
		for(i=0;i<MAX_PARTICIPANT_NUM;i++){
			if(party->participant[i].mixed && party->participant[i].id == m_cnid)
				break;
		}
		if(i==MAX_PARTICIPANT_NUM){			
			pthread_mutex_unlock(&party->conflock);
			return send_len;
		}
	}

	if(party->participant[i].p == OSAL_NULL || party->participant[i].ss == OSAL_NULL){
		pthread_mutex_unlock(&party->conflock);
		return send_len;
	}

	//OSAL_trace(eRTPP, eDebug, "rtpp_mixer_send_media_cb: participant[%s] index is %d, rtp's fd is %d, rtcp's fd is %d", 
								//party->participant[i].uid, i, party->participant[i].p->fd, party->participant[i].p->rtcpfd);
	
	if (m_data->type == kMixer_MT_RTP)
	{
		s_fd = party->participant[i].p->fd;
		memcpy(&saddr, &party->participant[i].addr[0], saddrlen);
	}
	else
	{
		s_fd = party->participant[i].p->rtcpfd;
		memcpy(&saddr, &party->participant[i].addr[1], saddrlen);

	}
	s_in = (struct sockaddr_in *)&saddr; 

	if(!strncmp(inet_ntoa(s_in->sin_addr),"127.0.0.1", strlen("127.0.0.1")) 
		|| !strncmp(inet_ntoa(s_in->sin_addr),"0.0.0.0", strlen("0.0.0.0")))
	{		
		pthread_mutex_unlock(&party->conflock);
		return send_len;
	}

	if ((send_len = sendto(s_fd, m_data->data, m_data->slen, 0, (const struct sockaddr *)&saddr, saddrlen)) < 0) 
	{
		OSAL_trace(eRTPP, eWarn,"participant[%s] socket[%d] send m_cnid[%d] packet[%d] to %s:%d faild!!\n",party->participant[i].uid, s_fd, m_cnid, m_data->type, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port));
		pthread_mutex_unlock(&party->conflock);
		return send_len;
	}
	else{
		party->participant[i].packetsSent++;
		//OSAL_trace(eRTPP, eDebug,"participant[%s] socket[%d] send m_cnid[%d] packet[%d] to %s:%d success!!\n",party->participant[i].uid, s_fd, m_cnid, m_data->type, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port));
	}

	pthread_mutex_unlock(&party->conflock);

	return send_len;
	
}



/*
void rtpp_mixer_send_media_cb(char* us_handle, int m_cnid, const media_data_t* m_data)
{
	int i;
	int s_fd = -1;
	OSAL_CHAR	keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *party;
	struct sockaddr saddr;
	struct sockaddr_in *s_in; 
	socklen_t saddrlen = sizeof(saddr);
	
	if (!m_data || !us_handle)
		return;

	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, us_handle, strlen(us_handle));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eDebug, "rtpp_mixer_send_media_cb: hash key = %s", keyBuff);
	party = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);
	if(party){
		for(i=0;i<MAX_PARTICIPANT_NUM;i++){
			if(party->participant[i].mixed && party->participant[i].id == m_cnid)
				break;
		}
		if(i==MAX_PARTICIPANT_NUM)
			return;
	}

	OSAL_trace(eRTPP, eDebug, "rtpp_mixer_send_media_cb: index is %d, rtp's fd is %d, rtcp's fd is %d", 
								i, party->participant[i].fd[0], party->participant[i].fd[1]);
	
	if (m_data->type == kMixer_MT_RTP)
	{
		s_fd = party->participant[i].fd[0];
		memcpy(&saddr, &party->participant[i].addr[0], saddrlen);
	}
	else
	{
		s_fd = party->participant[i].fd[1];
		memcpy(&saddr, &party->participant[i].addr[1], saddrlen);

	}
	s_in = (struct sockaddr_in *)&saddr; 

	if (sendto(s_fd, m_data->data, m_data->slen, 0, (const struct sockaddr *)&saddr, saddrlen) < 0) 
	{
		OSAL_trace(eRTPP, eWarn,"participant[%s] socket[%d] send m_cnid[%d] packet[%d] to %s:%d faild!!\n",party->participant[i].uid, s_fd, m_cnid, m_data->type, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port));
		return;
	}
	else{
		party->participant[i].packetsSent++;
		OSAL_trace(eRTPP, eDebug,"participant[%s] socket[%d] send m_cnid[%d] packet[%d] to %s:%d success!!\n",party->participant[i].uid, s_fd, m_cnid, m_data->type, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port));
	}
}

*/

void rtpp_mixer_recv_mix_media(OSAL_msgHdr *pMsg)
{
	int	rlen = 0;
	char rbuf[4096] = {0};
    struct sockaddr raddrin;
	struct sockaddr_in *s_in; 
    socklen_t raddrlen;
	media_type_t media_type;
	media_data_t mdata;

	if(pMsg == OSAL_NULL)
		return;
	
	OSAL_INT32 fd = pMsg->msgSubId;
	struct participant_info_t *participant = (struct participant_info_t *)pMsg->param2;

	if((participant == OSAL_NULL) || (participant->ss == OSAL_NULL) ||(participant->p == OSAL_NULL))
		return;

	if(fd == participant->p->fd){
		media_type = kMixer_MT_RTP;
	}
	else if(fd == participant->p->rtcpfd){
		media_type = kMixer_MT_RTCP;
	}
	else
		return;
	
	memset(rbuf, 0, sizeof(rbuf));	
	raddrlen = sizeof(raddrin);
    rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, &raddrin, &raddrlen);
	s_in = (struct sockaddr_in *)&raddrin;
	//OSAL_trace(eRTPP, eDebug,"fd:%d recv packet from %s:%d", fd, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port));
	if (rlen < 0) 
	{
        OSAL_trace(eRTPP, eError,"%s, recvfrom error len < 0\n", strerror(errno));
        return;
    }
    rbuf[rlen] = '\0'; 
	if(media_type == kMixer_MT_RTP)
		memcpy(&participant->addr[0], &raddrin, raddrlen);
	else
		memcpy(&participant->addr[1], &raddrin, raddrlen);

	participant->ttl = RtppGlobals.timeout;

	mdata.slen = rlen;
	mdata.data = rbuf;
	mdata.type = media_type;
	if(participant->mixed && (participant->id > -1))
	{
		if(Mixer_recv_media(participant->ss->inst, participant->id, &mdata) < 0){
			OSAL_trace(eRTPP, eError, "fail to receive data");
			return;
		}
		else{
			//OSAL_trace(eRTPP, eDebug, "rtpp_recv_mix_media: partipant[%s], fd[%d] success to receive data from %s:%d, len is %d, media_type is %d", 
						//participant->uid, fd, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port), rlen, media_type);
			participant->packetsReceived++;
		}
	}
	else
		OSAL_trace(eRTPP, eInfo, "no recieve the pt code, so don't recv media to mixer now.");
	
}


/*
void rtpp_mixer_recv_mix_media(OSAL_msgHdr *pMsg)
{
	int i;
	int	rlen = 0;
	char rbuf[4096] = {0};
    struct sockaddr raddrin;
	struct sockaddr_in *s_in; 
    socklen_t raddrlen;
	struct conference_info_t  *conf;
	media_type_t media_type;
	media_data_t mdata;

	if(pMsg == OSAL_NULL)
		return;
	
	OSAL_INT32 fd = pMsg->msgSubId;
	struct participant_info_t *participant = (struct participant_info_t *)pMsg->param2;

	if(participant == OSAL_NULL)
		return;

	conf = (struct conference_info_t *)participant->ss;

	if(participant->p == OSAL_NULL || conf == OSAL_NULL)
		return;

	for(i=0;i<MAX_PARTICIPANT_NUM;i++){
		if(conf->participant[i].p != OSAL_NULL){
			if(fd == conf->participant[i].p->fd){
				media_type = kMixer_MT_RTP;
				break;
			}
			else if(fd == conf->participant[i].p->rtcpfd){
				media_type = kMixer_MT_RTCP;
				break;
			}
		}
	}
	if(i == MAX_PARTICIPANT_NUM)
		return;
	
	memset(rbuf, 0, sizeof(rbuf));	
	raddrlen = sizeof(raddrin);
    rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, &raddrin, &raddrlen);
	s_in = (struct sockaddr_in *)&raddrin;
	//OSAL_trace(eRTPP, eDebug,"fd:%d recv packet from %s:%d", fd, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port));
	if (rlen < 0) 
	{
        OSAL_trace(eRTPP, eError,"%s, recvfrom error len < 0\n", strerror(errno));
        return;
    }
    rbuf[rlen] = '\0'; 
	if(media_type == kMixer_MT_RTP)
		memcpy(&conf->participant[i].addr[0], &raddrin, raddrlen);
	else
		memcpy(&conf->participant[i].addr[1], &raddrin, raddrlen);

	conf->participant[i].ttl = RtppGlobals.timeout;

	mdata.slen = rlen;
	mdata.data = rbuf;
	mdata.type = media_type;
	if(conf->participant[i].mixed && (conf->participant[i].id > -1))
	{
		if(Mixer_recv_media(conf->inst, conf->participant[i].id, &mdata) < 0){
			OSAL_trace(eRTPP, eError, "fail to receive data");
			return;
		}
		else{
			//OSAL_trace(eRTPP, eDebug, "rtpp_recv_mix_media: partipant[%s], fd[%d] success to receive data from %s:%d, len is %d, media_type is %d", 
						//conf->participant[i].uid, fd, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port), rlen, media_type);
			conf->participant[i].packetsReceived++;
		}
	}
	else
		OSAL_trace(eRTPP, eInfo, "no recieve the pt code, so don't recv media to mixer now.");
	
}
*/





/*
void rtpp_recv_mix_media(struct cfg *cf, int fd, struct conference_info_t* party, double dtime)
{
	int i;
	int	rlen = 0;
	char rbuf[4096] = {0};
    struct sockaddr raddrin;
	struct sockaddr_in *s_in; 
    socklen_t raddrlen;
	struct conference_info_t  *conf;
	media_type_t media_type;
	media_data_t mdata;
	
	if(!party)
		return;

	conf = (struct conference_info_t *)party;
	for(i=0;i<MAX_PARTICIPANT_NUM;i++){
		if(fd == conf->participant[i].fd[0]){
			media_type = kMixer_MT_RTP;
			break;
		}
		else if(fd == conf->participant[i].fd[1]){
			media_type = kMixer_MT_RTCP;
			break;
		}	
	}
	if(i == MAX_PARTICIPANT_NUM)
		return;
	
	memset(rbuf, 0, sizeof(rbuf));	
	raddrlen = sizeof(raddrin);
    rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, &raddrin, &raddrlen);
	s_in = (struct sockaddr_in *)&raddrin;
	OSAL_trace(eRTPP, eDebug,"fd:%d recv packet from %s:%d", fd, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port));
	if (rlen < 0) 
	{
        OSAL_trace(eRTPP, eError,"%s, recvfrom error len < 0\n", strerror(errno));
        return;
    }
    rbuf[rlen] = '\0'; 
	if(media_type == kMixer_MT_RTP)
		memcpy(&conf->participant[i].addr[0], &raddrin, raddrlen);
	else
		memcpy(&conf->participant[i].addr[1], &raddrin, raddrlen);

	conf->participant[i].ttl = cf->max_ttl;

	mdata.slen = rlen;
	mdata.data = rbuf;
	mdata.type = media_type;
	if(conf->participant[i].mixed && (conf->participant[i].id > -1))
	{
		if(Mixer_recv_media(conf->inst, conf->participant[i].id, &mdata) < 0){
			OSAL_trace(eRTPP, eError, "fail to receive data");
			return;
		}
		else{
			OSAL_trace(eRTPP, eDebug, "rtpp_recv_mix_media: partipant[%s], fd[%d] success to receive data from %s:%d, len is %d, media_type is %d", 
						conf->participant[i].uid, fd, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port), rlen, media_type);
			conf->participant[i].packetsReceived++;
		}
	}
	else
		OSAL_trace(eRTPP, eInfo, "no recieve the pt code, so don't recv media to mixer now.");
	
}void rtpp_recv_mix_media(struct cfg *cf, int fd, struct conference_info_t* party, double dtime)
{
	int i;
	int	rlen = 0;
	char rbuf[4096] = {0};
    struct sockaddr raddrin;
	struct sockaddr_in *s_in; 
    socklen_t raddrlen;
	struct conference_info_t  *conf;
	media_type_t media_type;
	media_data_t mdata;
	
	if(!party)
		return;

	conf = (struct conference_info_t *)party;
	for(i=0;i<MAX_PARTICIPANT_NUM;i++){
		if(fd == conf->participant[i].fd[0]){
			media_type = kMixer_MT_RTP;
			break;
		}
		else if(fd == conf->participant[i].fd[1]){
			media_type = kMixer_MT_RTCP;
			break;
		}	
	}
	if(i == MAX_PARTICIPANT_NUM)
		return;
	
	memset(rbuf, 0, sizeof(rbuf));	
	raddrlen = sizeof(raddrin);
    rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, &raddrin, &raddrlen);
	s_in = (struct sockaddr_in *)&raddrin;
	OSAL_trace(eRTPP, eDebug,"fd:%d recv packet from %s:%d", fd, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port));
	if (rlen < 0) 
	{
        OSAL_trace(eRTPP, eError,"%s, recvfrom error len < 0\n", strerror(errno));
        return;
    }
    rbuf[rlen] = '\0'; 
	if(media_type == kMixer_MT_RTP)
		memcpy(&conf->participant[i].addr[0], &raddrin, raddrlen);
	else
		memcpy(&conf->participant[i].addr[1], &raddrin, raddrlen);

	conf->participant[i].ttl = cf->max_ttl;

	mdata.slen = rlen;
	mdata.data = rbuf;
	mdata.type = media_type;
	if(conf->participant[i].mixed && (conf->participant[i].id > -1))
	{
		if(Mixer_recv_media(conf->inst, conf->participant[i].id, &mdata) < 0){
			OSAL_trace(eRTPP, eError, "fail to receive data");
			return;
		}
		else{
			OSAL_trace(eRTPP, eDebug, "rtpp_recv_mix_media: partipant[%s], fd[%d] success to receive data from %s:%d, len is %d, media_type is %d", 
						conf->participant[i].uid, fd, inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port), rlen, media_type);
			conf->participant[i].packetsReceived++;
		}
	}
	else
		OSAL_trace(eRTPP, eInfo, "no recieve the pt code, so don't recv media to mixer now.");
	
}

*/


#if 0
OSAL_INT32 rtpp_allocate_port(int *port, int *fds, struct sockaddr *laddr)
{
    struct sockaddr *lia;

	lia = RtppGlobals.cfg.bindaddr[0];
	if (RtppGlobals.cfg.nf_mode == NF_MODE_OFF)
	{
		if(laddr)
			lia = laddr;
		if(create_listener(&RtppGlobals.cfg, lia, port, fds) == -1) {
			 OSAL_trace(eRTPP, eError, "can't create listener.");
			 return -1;
		}
	}

	return 0;
}
#endif


OSAL_INT32 rtpp_convert_to_conference(OSAL_CHAR *call_cookie, OSAL_msgHdr *pMsg)
{
	struct conference_info_t party;
	OSAL_CHAR keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;
	struct conference_info_t *pcreate = NULL;
	struct participant_info_t *spb, *spc;
	char *old_cookie, *from_tag, *to_tag;
	int from_partid, to_partid;
	rtpp_session_t *spa;
	char tmp[10];
	char *q;
	char content[512];
	char *bak = content;
	int len = 0;
	char cmd = 'p';

	OSAL_INT32 argc;
	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_CHAR *cookie;

	if(!call_cookie || !pMsg)
		return OSAL_ERROR;

	OSAL_INT32 mod_id = pMsg->msgSubId;
	OSAL_INT32 fip = pMsg->param;
	OSAL_UINT16 fport = pMsg->param2;
	OSAL_CHAR *msg = (OSAL_CHAR  *)pMsg->pContent;
	OSAL_INT32 lenth = pMsg->contentLen;

	command_parse(msg,lenth,argv,&argc);
	
	if(argc != 5){
		OSAL_trace (eRTPP, eError, "err format %s",msg);
		return OSAL_ERROR;
	}else{
		cookie = argv[0];
		old_cookie = argv[2];
	}

	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie,  OSAL_strnLen(call_cookie, MAX_COOKIE_LEN));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_convert_to_conference: hash key = %s", keyBuff);
	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(!pHash)				
	{				
		//resolve callid, from_tag, to_tag;
		q = strrchr(argv[3],'@');
		memset(tmp, 0, sizeof(tmp));
		if(q){
			strncpy(tmp, argv[3], q-argv[3]);
			from_partid = atoi(tmp);
			q++;
			from_tag = q;
		}else{
			OSAL_trace(eRTPP, eError,  "fail to get from_tag.");
			return OSAL_ERROR;
		}

		q = strrchr(argv[4],'@');
		memset(tmp, 0, sizeof(tmp));
		if(q){
			strncpy(tmp, argv[4], q-argv[4]);
			to_partid = atoi(tmp);
			q++;
			to_tag = q;
		}else{
			OSAL_trace(eRTPP, eError,  "fail to get to_tag.");
			return OSAL_ERROR;
		}
		//find session by callid
		if(rtpp_find_session(old_cookie, &spa) != 0){
			OSAL_trace(eRTPP, eError, "can't find the session from_tag[%s] to_tag[%s] by old cookie[%s]", from_tag, to_tag, old_cookie);				
			return OSAL_ERROR;
		}

		memset(&party, 0, sizeof(struct conference_info_t));
		strcpy(party.call_cookie, keyBuff);	
		strcpy(party.notify, spa->notify);
		pcreate = (struct conference_info_t *)OSAL_hashAdd(conferenceHashTable, keyBuff, &party, OSAL_FALSE);
		if(pcreate)
		{
			OSAL_trace(eRTPP, eInfo, "add conference cookie:%s to HashTable.", party.call_cookie);			
			pcreate->ttl = time(NULL);
			memset(content, 0, sizeof(content));
			len = sprintf(bak, "%c 0", cmd);
			bak += len;

			init_rtpp_conf_session(pcreate);				
			if(from_tag){
				spb = get_rtpp_conf_session(pcreate);
				if (spb == OSAL_NULL) 
				{
					OSAL_trace(eRTPP, eError, "no session to allcate");
				    return OSAL_ERROR;
				}
				spb->valid = 1;
				spb->partid = from_partid;
				strcpy(spb->uid, from_tag);
				strcpy(spb->partid_uid, argv[3]);
				spb->p = spa->left.audio[0].p;
				if(rtpp_disselct_port(mod_id, spa->left.audio[0].p) < 0){
					OSAL_trace(eRTPP, eError, "fail to disselect  normal fd");
					return OSAL_ERROR;
				}
				if(rtpp_mixer_selct_port(mod_id, spb) < 0){
					OSAL_trace(eRTPP, eError, "fail to select mix fd");
					return OSAL_ERROR;
				}
				spb->ss = pcreate;
				OSAL_trace(eRTPP, eInfo, "add participant %s to conference", spb->uid);			
				len = sprintf(bak, " %d@%d", spb->partid, spb->p->port);
				bak += len;
			}			
			if(to_tag){
				spc = get_rtpp_conf_session(pcreate);
				if (spc == OSAL_NULL) 
				{
					OSAL_trace(eRTPP, eError, "no session to allcate");
				    return OSAL_ERROR;
				}
				spc->valid = 1;
				spc->partid = to_partid;
				strcpy(spc->uid, to_tag);
				strcpy(spc->partid_uid, argv[4]);
				spc->p = spa->right.audio[0].p;
				if(rtpp_disselct_port(mod_id, spa->right.audio[0].p) < 0){
					OSAL_trace(eRTPP, eError, "fail to disselect normal fd");
					return OSAL_ERROR;
				}					
				if(rtpp_mixer_selct_port(mod_id, spc) < 0){
					OSAL_trace(eRTPP, eError, "fail to select mix fd");
					return OSAL_ERROR;
				}				
				spc->ss = pcreate;
				OSAL_trace(eRTPP, eInfo, "add participant %s to conference", spc->uid);			
				len = sprintf(bak, " %d@%d", spc->partid, spc->p->port);
				bak += len;
			}	
			if(from_tag && to_tag){
				OSAL_trace(eRTPP, eInfo, "del call_cookie[%s] ftag[%s] ttag[%s]", call_cookie, from_tag, to_tag);
				rtpp_free_old_session(spa);
			}

			if((pcreate->inst = Mixer_create_conference(pcreate)) == NULL){
				OSAL_trace(eRTPP, eError, "fail to create mixer conference");
				return OSAL_ERROR;
			}

			pcreate->mod_id = mod_id;
			pcreate->from_ip = fip;		
			rtpp_start_conf_media_time(pcreate);
			
			m_cmd_repond (cookie, content, fip, fport);
			OSAL_trace(eRTPP, eSys, "creat conference cookie is %s", pcreate->call_cookie);
		
		}
		else{
		    OSAL_trace(eRTPP, eError,  "add conference cookie:%s to hash table failed.", party.call_cookie);
			return OSAL_ERROR;
		}
	}
	else{
		OSAL_trace(eRTPP, eError, "this conference cookie:%s has created before.", keyBuff);
		return OSAL_ERROR;
	}

	return OSAL_OK;
}
 

#if 0
OSAL_INT32 rtpp_convert_to_conference(char *call_cookie, char *cookie, int argc, char *argv[], struct sockaddr *laddr, OSAL_INT32 fip, struct sockaddr_storage *raddr)
{
	struct conference_info_t party;
	OSAL_CHAR	 keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;
	struct conference_info_t *pcreate = NULL;
	struct participant_info_t *spb, *spc;
	char *old_cookie, *from_tag, *to_tag;
	int from_partid, to_partid;
	struct rtpp_session *spa;
	char *notify_buf;
	char tmp[10];
	char *q;
	int rlen;
	char content[512];
	char *bak = content;
	int len = 0;
	char cmd = 'p';

	if(!call_cookie || !cookie ||!raddr || argc < 4)
		return OSAL_ERROR;
	if(!argv[1] || !argv[2] || !argv[3])
		return OSAL_ERROR;

	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, strlen(call_cookie));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_convert_to_conference: hash key = %s", keyBuff);


	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(!pHash)				
	{				
		//resolve callid, from_tag, to_tag;
		old_cookie = argv[1];
		q = strrchr(argv[2],'@');
		memset(tmp, 0, sizeof(tmp));
		if(q){
			strncpy(tmp, argv[2], q-argv[2]);
			from_partid = atoi(tmp);
			q++;
			from_tag = q;
		}else{
			OSAL_trace(eRTPP, eError,  "fail to get from_tag.");
			return OSAL_ERROR;
		}

		q = strrchr(argv[3],'@');
		memset(tmp, 0, sizeof(tmp));
		if(q){
			strncpy(tmp, argv[3], q-argv[3]);
			to_partid = atoi(tmp);
			q++;
			to_tag = q;
		}else{
			OSAL_trace(eRTPP, eError,  "fail to get to_tag.");
			return OSAL_ERROR;
		}
		//find session by callid
		if(find_stream(&RtppGlobals.cfg, old_cookie, from_tag, to_tag, &spa) < 0){
			OSAL_trace(eRTPP, eError, "can't find the session from_tag[%s] to_tag[%s] by old cookie[%s]", from_tag, to_tag, old_cookie);				
			return OSAL_ERROR;
		}

		memset(&party, 0, sizeof(struct conference_info_t));
		strcpy(party.call_cookie, keyBuff);	
		party.timeout_data.handler = spa->timeout_data.handler;
		OSAL_trace(eRTPP, eInfo, "setting notify timeout handler OK");			
		party.timeout_data.notify_tag = NULL;		
		if(spa->timeout_data.notify_tag){
			notify_buf = strchr(spa->timeout_data.notify_tag, ':');
			if(notify_buf){
				notify_buf++;
				if(notify_buf){
					party.timeout_data.notify_tag = (char *)malloc(strlen(notify_buf)+1);
			        if (party.timeout_data.notify_tag == NULL) {
						OSAL_trace(eRTPP, eError, "no memory to allcate");
			            return OSAL_ERROR;
			        }
					memset(party.timeout_data.notify_tag, 0, strlen(notify_buf)+1);
					strncpy(party.timeout_data.notify_tag, notify_buf, strlen(notify_buf));
					OSAL_trace(eRTPP, eInfo, "setting timeout notify_tag[%s] OK", party.timeout_data.notify_tag);						
				}
			}
		}
		if(party.timeout_data.notify_tag == NULL){
			OSAL_trace(eRTPP, eError, "notify tag is NULL.");
			return OSAL_ERROR;
		}
		
		pcreate = (struct conference_info_t *)OSAL_hashAdd(conferenceHashTable, keyBuff, &party, OSAL_FALSE);
		if(pcreate)
		{
			OSAL_trace(eRTPP, eInfo, "add conference cookie:%s to HashTable.", party.call_cookie);			
			pcreate->ttl = time(NULL);
			memset(content, 0, sizeof(content));
			len = sprintf(bak, "%c 0", cmd);
			bak += len;

			init_rtpp_conf_session(pcreate);				
			if(from_tag){
				spb = get_rtpp_conf_session(pcreate);
				if (spb == OSAL_NULL) 
				{
					OSAL_trace(eRTPP, eError, "no session to allcate");
				    return OSAL_ERROR;
				}
				spb->valid = 1;
				spb->partid = from_partid;
				strcpy(spb->uid, from_tag);
				strcpy(spb->partid_uid, argv[2]);
/*				
				if(rtpp_allocate_port(&spb->port, fds, laddr) < 0)
					OSAL_trace(eRTPP, eError, "allocat port err");
				spb->fd[0] = fds[0];
				spb->fd[1] = fds[1];
*/
				spb->port = spa->ports[1];
				spb->fd[0] = spa->fds[1];
				spb->fd[1] = spa->rtcp->fds[1];
				poll_remove_session(spa, 1);
				poll_remove_session(spa->rtcp, 1);
				if(poll_append_conf_session(pcreate, spb->index, 0) < 0)
					OSAL_trace(eRTPP, eError, "poll session rtp fd err");					
				if(poll_append_conf_session(pcreate, spb->index, 1) < 0)
					OSAL_trace(eRTPP, eError, "poll session rtcp fd err");	
/*				
				mp.m_pt = spb->pt;
				if((spb->id = Mixer_add_participant(pcreate->inst, &mp)) < 0){
					OSAL_trace(eRTPP, eError, "fail to add mixer participant");
					return OSAL_ERROR;
				}				
				spb->mixed = 1;
*/
				OSAL_trace(eRTPP, eInfo, "add participant %s to conference", spb->uid);			
				len = sprintf(bak, " %d@%d", spb->partid, spb->port);
				bak += len;
			}			
			if(to_tag){
				spc = get_rtpp_conf_session(pcreate);
				if (spc == OSAL_NULL) 
				{
					OSAL_trace(eRTPP, eError, "no session to allcate");
				    return OSAL_ERROR;
				}
				spc->valid = 1;
				spc->partid = to_partid;
				strcpy(spc->uid, to_tag);
				strcpy(spc->partid_uid, argv[3]);
/*				
				if(rtpp_allocate_port(&spc->port, fds, laddr) < 0)
					OSAL_trace(eRTPP, eError, "allocat port err");
				spc->fd[0] = fds[0];
				spc->fd[1] = fds[1];
*/
				spc->port = spa->ports[0];
				spc->fd[0] = spa->fds[0];
				spc->fd[1] = spa->rtcp->fds[0];
				poll_remove_session(spa, 0);
				poll_remove_session(spa->rtcp, 0);
				if(poll_append_conf_session(pcreate, spc->index, 0) < 0)
					OSAL_trace(eRTPP, eError, "poll session rtp fd err");					
				if(poll_append_conf_session(pcreate, spc->index, 1) < 0)
					OSAL_trace(eRTPP, eError, "poll session rtcp fd err");
/*				
				mp.m_pt = spc->pt;
				if((spc->id = Mixer_add_participant(pcreate->inst, &mp)) < 0){
					OSAL_trace(eRTPP, eError, "fail to add mixer participant");
					return OSAL_ERROR;
				}				
				spc->mixed = 1;
*/
				OSAL_trace(eRTPP, eInfo, "add participant %s to conference", spc->uid);			
				len = sprintf(bak, " %d@%d", spc->partid, spc->port);
				bak += len;
			}	
			if(from_tag && to_tag){
				OSAL_trace(eRTPP, eInfo, "del call_cookie[%s] ftag[%s] ttag[%s]", call_cookie, from_tag, to_tag);
				delete_old_session(&RtppGlobals.cfg, old_cookie, from_tag, to_tag, 0);
			}

			if((pcreate->inst = Mixer_create_conference(pcreate->call_cookie)) == NULL){
				OSAL_trace(eRTPP, eError, "fail to create mixer conference");
				return OSAL_ERROR;
			}
			
			rlen = sizeof(struct sockaddr_storage);
			m_cmd_repond(&RtppGlobals.cfg, fd, raddr, rlen, cookie, content);			
		}
		else{
		    OSAL_trace(eRTPP, eError,  "add conference cookie:%s to hash table failed.", party.call_cookie);
			return OSAL_ERROR;
		}
	}
	else{
		OSAL_trace(eRTPP, eError, "this conference cookie:%s has created before.", keyBuff);
		return OSAL_ERROR;
	}

	return OSAL_OK;
}
#endif

OSAL_INT32 rtpp_creat_conference(OSAL_CHAR *call_cookie, OSAL_msgHdr *pMsg)
{
	OSAL_INT32 i;
	OSAL_CHAR content[512];
	OSAL_CHAR *bak = content;
    OSAL_INT32 len = 0;
	OSAL_CHAR cmd = 'c';

	struct conference_info_t party;
	OSAL_CHAR keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;
	struct conference_info_t *pcreate = NULL;
	struct participant_info_t *sp;

	OSAL_INT32 argc;
	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_CHAR *cookie,*op, *notify, *tmp;
	OSAL_INT32 rtpp_index = 0;
	OSAL_INT32 link_flags = 0;
	OSAL_CHAR link_ip[RTPP_MAX_IP_LEN] = {0};
	OSAL_INT32 complete_flags = 0;
	OSAL_INT32 asym_flags = 0;

	if(!call_cookie || !pMsg)
		return OSAL_ERROR;
	
	OSAL_INT32 mod_id = pMsg->msgSubId;
	OSAL_INT32 fip = pMsg->param;
	OSAL_UINT16 fport = pMsg->param2;
	OSAL_CHAR *msg = (OSAL_CHAR  *)pMsg->pContent;
	OSAL_INT32 lenth = pMsg->contentLen;

	command_parse(msg,lenth,argv,&argc);
	
	if(argc < 3){
		OSAL_trace (eRTPP, eError, "err format %s",msg);
		return OSAL_ERROR;
	}else{
		cookie = argv[0];
		op = argv[1];
		notify = argv[2];
	}

	//op proc
	for(tmp = op +2; *tmp; tmp++){
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
		
			default:
				OSAL_trace(eRTPP, eError, "unknown command option '%c'",*tmp);
				break;
   		}
	}

	if(link_flags && (rtpp_index = check_link_addr(link_ip)) < 0){
		OSAL_trace(eRTPP, eError, "ip %s is not in this rtpp",link_ip);
		return OSAL_ERROR;
	}

	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, OSAL_strnLen(call_cookie, MAX_COOKIE_LEN));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_creat_conference: hash key = %s", keyBuff);

	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(!pHash)				
	{				
		memset(&party, 0, sizeof(struct conference_info_t));
		strcpy(party.call_cookie, keyBuff);

		if(notify){		
			strncpy(party.notify,notify, OSAL_strnLen(notify, RTPP_MAX_NOTIFY_LEN));
			OSAL_trace(eRTPP, eInfo, "setting notify[%s] OK", party.notify);				
		}

		pthread_mutex_lock(&rtpp_conf_hashtable_lock);
		pcreate = (struct conference_info_t *)OSAL_hashAdd(conferenceHashTable, keyBuff, &party, OSAL_FALSE);
		pthread_mutex_unlock(&rtpp_conf_hashtable_lock);

		if(pcreate)
		{
			OSAL_trace(eRTPP, eInfo, "add conference cookie:%s to HashTable.", party.call_cookie);
			pcreate->ttl = time(NULL);
			memset(content, 0, sizeof(content));
			len = sprintf(bak, "%c 0", cmd);
			bak += len;
			
			init_rtpp_conf_session(pcreate);
			for(i=0;argc > 3 && i<argc-3 && argv[i+3];i++)
			{
				char *q = strrchr(argv[i+3],'@');
				char tmp[10] = {0};
				if(q){
					sp = get_rtpp_conf_session(pcreate);
					if (sp == OSAL_NULL) 
					{
						OSAL_trace(eRTPP, eError, "no session to allcate");
					    return OSAL_ERROR;
					}
					sp->valid = 1;
					strncpy(tmp, argv[i+3], q-argv[i+3]);
					int num = atoi(tmp);
					q++;
					sp->partid = num;
					strcpy(sp->uid, q);
					strcpy(sp->partid_uid, argv[i+3]);
					if(rtpp_mixer_selct_alloc_port(mod_id, rtpp_index, sp) < 0){
						OSAL_trace(eRTPP, eError, "allocat port err");
						return OSAL_ERROR;
					}
					sp->ss = pcreate;

					OSAL_trace(eRTPP, eDebug, "create participant %s, index is %d, fd is %d, rtcpfd is %d",
												sp->uid, sp->index,sp->p->fd,sp->p->rtcpfd);
					
					OSAL_trace(eRTPP, eInfo, "add participant %s to conference", sp->uid);				
					len = sprintf(bak, " %d@%d", sp->partid, sp->p->port);
					bak += len;
				}		
			}
				
			//if((pcreate->inst = Mixer_create_conference(pcreate->call_cookie)) == NULL){
			if((pcreate->inst = Mixer_create_conference(pcreate)) == NULL){
				OSAL_trace(eRTPP, eError, "fail to create mixer conference");
				return OSAL_ERROR;
			}

			pcreate->mod_id = mod_id;
			pcreate->from_ip = fip;			
			rtpp_start_conf_media_time(pcreate);
		
			m_cmd_repond (cookie, content, fip, fport);
			OSAL_trace(eRTPP, eDebug, "rtpp_creat_conference: pcreate->inst addr is %p", pcreate->inst);
			OSAL_trace(eRTPP, eSys, "creat conference cookie is %s", pcreate->call_cookie);			
		}
		else{
		    OSAL_trace(eRTPP, eError,  "add conference cookie:%s to hash table failed.", party.call_cookie);			
			return OSAL_ERROR;
		}
	}
	else{
		OSAL_trace(eRTPP, eError, "this conference cookie:%s has created before.", keyBuff);
		return OSAL_ERROR;
	}

	return OSAL_OK;

}


/*
OSAL_INT32 rtpp_creat_conference(char *call_cookie, char *cookie, int argc, char *argv[], struct sockaddr *laddr, int fd, struct sockaddr_storage *raddr)
{
	struct conference_info_t party;
	OSAL_CHAR	keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;
	struct conference_info_t *pcreate = NULL;
	struct participant_info_t *sp;
	char *cp;
	int fds[2];
	char *notify_tag;  
	int i;
	int rlen;
	char content[512];
	char *bak = content;
    int len = 0;
    int nlen = 0;
	char cmd = 'c';

	if(!call_cookie || !cookie ||!raddr || argc < 2)
		return OSAL_ERROR;

	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, strlen(call_cookie));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_creat_conference: hash key = %s", keyBuff);

	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(!pHash)				
	{				
		memset(&party, 0, sizeof(struct conference_info_t));
		strcpy(party.call_cookie, keyBuff);

		if(argv[1]){
			notify_tag = argv[1];
			nlen = url_unquote((uint8_t *)notify_tag, strlen(notify_tag));
			if (nlen == -1) 
			{
			    OSAL_trace(eRTPP, eError, "command syntax error - invalid URL encoding");
				return OSAL_ERROR;
			}
			notify_tag[nlen] = '\0';			
			party.timeout_data.notify_tag = strdup(notify_tag);
			OSAL_trace(eRTPP, eInfo,
				"setting timeout notify_tag[%s] OK", party.timeout_data.notify_tag);				
		}

		for(i=0; i<RtppGlobals.cfg.timeout_socket_num; i++)  {	
			cp = strchr(RtppGlobals.cfg.timeout_handler[i]->socket_name, ':');
			OSAL_trace(eRTPP, eDebug, "from addr is %s, notify sock name is %s", 
				inet_ntoa((satosin(raddr))->sin_addr), RtppGlobals.cfg.timeout_handler[i]->socket_name);
			OSAL_trace(eRTPP, eDebug, "len is %d", cp - RtppGlobals.cfg.timeout_handler[i]->socket_name);					
			if(!strncmp(inet_ntoa((satosin(raddr))->sin_addr), RtppGlobals.cfg.timeout_handler[i]->socket_name, 
				(int)(cp-RtppGlobals.cfg.timeout_handler[i]->socket_name)))
			{
				party.timeout_data.handler = RtppGlobals.cfg.timeout_handler[i];
				OSAL_trace(eRTPP, eInfo, "setting notify timeout handler OK");				
				break;
			}
		}
		if(i == RtppGlobals.cfg.timeout_socket_num)  {
			party.timeout_data.handler = NULL;			
			OSAL_trace(eRTPP, eWarn, "timeout handle is NULL");
		}

		pcreate = (struct conference_info_t *)OSAL_hashAdd(conferenceHashTable, keyBuff, &party, OSAL_FALSE);
		if(pcreate)
		{
			OSAL_trace(eRTPP, eInfo, "add conference cookie:%s to HashTable.", party.call_cookie);
			pcreate->ttl = time(NULL);
			memset(content, 0, sizeof(content));
			len = sprintf(bak, "%c 0", cmd);
			bak += len;
			
			init_rtpp_conf_session(pcreate);
			for(i=0;argc > 2 && i<argc-2 && argv[i+2];i++)
			{
				char *q = strrchr(argv[i+2],'@');
				char tmp[10] = {0};
				if(q){
					sp = get_rtpp_conf_session(pcreate);
					if (sp == OSAL_NULL) 
					{
						OSAL_trace(eRTPP, eError, "no session to allcate");
					    return OSAL_ERROR;
					}
					sp->valid = 1;
					strncpy(tmp, argv[i+2], q-argv[i+2]);
					int num = atoi(tmp);
					q++;
					sp->partid = num;
					strcpy(sp->uid, q);
					strcpy(sp->partid_uid, argv[i+2]);
					if(rtpp_allocate_port(&sp->port, fds, laddr) < 0)
						OSAL_trace(eRTPP, eError, "allocat port err");
					sp->fd[0] = fds[0];
					sp->fd[1] = fds[1];
					OSAL_trace(eRTPP, eDebug, "create participant %s, index is %d, fd[0] is %d, fd[1] is %d",
												sp->uid, sp->index,sp->fd[0],sp->fd[1]);
					if(poll_append_conf_session(pcreate, sp->index, 0) < 0)
						OSAL_trace(eRTPP, eError, "poll session rtp fd err");					
					if(poll_append_conf_session(pcreate, sp->index, 1) < 0)
						OSAL_trace(eRTPP, eError, "poll session rtcp fd err");	
					
					OSAL_trace(eRTPP, eInfo, "add participant %s to conference", sp->uid);				
					len = sprintf(bak, " %d@%d", sp->partid, sp->port);
					bak += len;
				}		
			}
			
			rlen = sizeof(struct sockaddr_storage);
			m_cmd_repond(&RtppGlobals.cfg, fd, raddr, rlen, cookie, content);
	
			if((pcreate->inst = Mixer_create_conference(pcreate->call_cookie)) == NULL){
				OSAL_trace(eRTPP, eError, "fail to create mixer conference");
				return OSAL_ERROR;
			}
			OSAL_trace(eRTPP, eDebug, "rtpp_creat_conference: messi debug pcreate->inst addr is %p", pcreate->inst);			
		}
		else
		    OSAL_trace(eRTPP, eError,  "add conference cookie:%s to hash table failed.", party.call_cookie);
			
	}
	else{
		OSAL_trace(eRTPP, eError, "this conference cookie:%s has created before.", keyBuff);
		return OSAL_ERROR;
	}

	return OSAL_OK;

}
*/

#if 0
OSAL_INT32 rtpp_allocate_source(char *call_cookie, char *cookie, int argc, char *argv[], struct sockaddr *laddr, int fd, struct sockaddr_storage *raddr)
{
	int i, n, rlen;
	int lport = 0;
	int rport = 0;
	int rfds[2], lfds[2];
	int pf, weak = 0;
	char *cp;
	char *uid;
	struct sockaddr *lia[2], *ia[4];
	struct rtpp_session *spa, *spb;
	char notify_str[128] = {0};
	char content[32];
	char cmd = 'u';

	if(!call_cookie || !cookie ||!raddr || argc < 7)
		return OSAL_ERROR;

	spa = session_findfirst(&RtppGlobals.cfg, call_cookie);
	if(spa == OSAL_NULL){
		OSAL_trace(eRTPP, eError, "the cookie: %s has exsited.", call_cookie);
		return OSAL_ERROR;
	}

	lia[0] = lia[1] = RtppGlobals.cfg.bindaddr[0];

	uid = strrchr(argv[2],'@');
	if(uid)
		uid++;

	if (argv[3] != OSAL_NULL && argv[4] != OSAL_NULL && strlen(argv[3]) >= 7) 
	{
		struct sockaddr_storage tia;
	
		 if ((n = resolve(sstosa(&tia), pf, argv[3], argv[4], AI_NUMERICHOST)) == 0) 
		 {
			if (!ishostnull(sstosa(&tia))) 
			{
				for (i = 0; i < 2; i++) 
				{
					ia[i] = (struct sockaddr *)osal_allocate(SS_LEN(&tia),DEFAULT_FLAGS, mem_default,
							MAGIC_NUMBER('R','T','s','a'), NULL);
					if (ia[i] == OSAL_NULL) 
					{
						OSAL_trace(eRTPP, eError, "fail to allocate memory");							
						return 5;
					}
					memcpy(ia[i], &tia, SS_LEN(&tia));
				}	
				/* Set port for RTCP, will work both for IPv4 and IPv6 */
				n = ntohs(satosin(ia[1])->sin_port);
				satosin(ia[1])->sin_port = htons(n + 1);
				OSAL_trace(eRTPP, eDebug, "addr[%s:%s]", argv[3], argv[4]);
			 }
		} 
		else 
		{
				OSAL_trace(eRTPP, eError, "getaddrinfo: %s", gai_strerror(n));
				return OSAL_ERROR;
		}
	}
	
	if (argv[5] != OSAL_NULL && argv[6] != OSAL_NULL && strlen(argv[5]) >= 7) 
	{
		struct sockaddr_storage tia;
	
		 if ((n = resolve(sstosa(&tia), pf, argv[5], argv[6], AI_NUMERICHOST)) == 0) 
		 {
			if (!ishostnull(sstosa(&tia))) 
			{
				for (i = 2; i < 4; i++) 
				{
					ia[i] = (struct sockaddr *)osal_allocate(SS_LEN(&tia),DEFAULT_FLAGS, mem_default,
							MAGIC_NUMBER('R','T','s','a'), NULL);
					if (ia[i] == OSAL_NULL) 
					{
						OSAL_trace(eRTPP, eError, "fail to allocate memory");	
						 return 0;
					}
					memcpy(ia[i], &tia, SS_LEN(&tia));
				}	
				/* Set port for RTCP, will work both for IPv4 and IPv6 */
				n = ntohs(satosin(ia[3])->sin_port);
				satosin(ia[3])->sin_port = htons(n + 1);
				OSAL_trace(eRTPP, eDebug, "addr[%s:%s]", argv[5], argv[6]);
			 }
		} 
		else 
		{
				OSAL_trace(eRTPP, eError, "getaddrinfo: %s", gai_strerror(n));
				return OSAL_ERROR;
		}
	}	


	OSAL_trace(eRTPP, eInfo,"new session %s, tag %s requested",call_cookie, uid);
		
	if (laddr != OSAL_NULL) {
		lia[0] = lia[1] = laddr;
		if (lia[0] == OSAL_NULL) {
			OSAL_trace(eRTPP, eInfo,"can't create listener");		
			return 10;
		}
	}
	
	if(RtppGlobals.cfg.nf_mode == NF_MODE_OFF)
	{
		if(create_listener(&RtppGlobals.cfg, lia[0], &rport, rfds) == -1) {
			OSAL_trace(eRTPP, eError, "can't create listener.");
			return 10;
		}			
		if(create_listener(&RtppGlobals.cfg, lia[0], &lport, lfds) == -1) {
			OSAL_trace(eRTPP, eError, "can't create listener.");
			return 10;
		}	

	}

	spa = get_rtpp_session();
	if (spa == OSAL_NULL) 
	{
		OSAL_trace(eRTPP, eError, "no enough session.");
		return 11;
	}
	spb= get_rtpp_session();
	if (spb == OSAL_NULL) 
	{
		OSAL_trace(eRTPP, eError, "no enough session.");
		return 12;
	}

	spa->rand_num = spb->rand_num = get_rand_num();
	//spa->rtpp_mid_flag = 0;	
	for (i = 0; i < 2; i++) 
	{
		spa->fds[i] = spb->fds[i] = -1;
		spa->last_update[i] = 0;
		spb->last_update[i] = 0;
	}
	spa->call_id = osal_allocate(strlen(call_cookie) + 1, DEFAULT_FLAGS, mem_default,
							MAGIC_NUMBER('R','T','s','t'), NULL);
	if (spa->call_id == OSAL_NULL) 
	{
		OSAL_trace(eRTPP, eError, "fail to allocate memory");
		return 13;
	}
	strcpy(spa->call_id, call_cookie);
	spb->call_id = spa->call_id;
	
	spa->tag = osal_allocate(strlen(uid) + 1, DEFAULT_FLAGS, mem_default,
							MAGIC_NUMBER('R','T','s','t'), NULL);
	if (spa->tag == OSAL_NULL) 
	{
		OSAL_trace(eRTPP, eError, "fail to allocate memory");
		return 14;

	}
	strcpy(spa->tag, uid);
	spb->tag = spa->tag;


	spa->from_tag = osal_allocate(strlen(uid)+3, DEFAULT_FLAGS, mem_default,
				MAGIC_NUMBER('R', 'T', 's', 't'), NULL);
	spa->to_tag = osal_allocate(strlen(uid)+3, DEFAULT_FLAGS, mem_default,
				MAGIC_NUMBER('R', 'T', 's', 't'), NULL);
	if(spa->from_tag) {
		strcpy(spa->from_tag, uid);
		strcat(spa->from_tag, ":1");
		spa->rtcp->from_tag = spa->from_tag;
	}
	if(spa->to_tag) {
		strcpy(spa->to_tag, uid);
		strcat(spa->to_tag, ":0");
		spa->rtcp->to_tag = spa->to_tag;
	}	
	OSAL_trace(eRTPP, eDebug, "conference update: from_tag[%s] to_tag[%s]", spa->from_tag, spa->to_tag);


	
	for (i = 0; i < 2; i++) 
	{
		spa->rrcs[i] = OSAL_NULL;
		spb->rrcs[i] = OSAL_NULL;
		spa->laddr[i] = lia[i];
		spb->laddr[i] = lia[i];
	}
	
	spa->strong = spa->weak[0] = spa->weak[1] = 0;
	if (weak)
		spa->weak[0] = 1;
	else
		spa->strong = 1;
	spa->fds[0] = rfds[0];
	spa->fds[1] = lfds[0];
	spb->fds[0] = rfds[1];
	spb->fds[1] = lfds[1];
	spa->ports[0] = rport;
	spa->ports[1] = lport;
	spb->ports[0] = rport + 1;
	spb->ports[1] = lport + 1;
	spa->ttl[0] = RtppGlobals.cfg.max_ttl;
	spa->ttl[1] = RtppGlobals.cfg.max_ttl;
	spb->ttl[0] = -1;
	spb->ttl[1] = -1;
	spa->rtcp = spb;
	spb->rtcp = OSAL_NULL;
	spa->rtp = OSAL_NULL;
	spb->rtp = spa;
	spa->rtpp_session_type = VPS_SESSION;
	spa->rtpp_music_flag = RTPP_MUSIC_PLAY_OFF;
	spa->ttl_mode = RtppGlobals.cfg.ttl_mode;
	spa->complete = spa->rtcp->complete = RTPP_200OK;	//200OK

	if (RtppGlobals.cfg.nf_mode == NF_MODE_OFF) {
		poll_append_session(spa, 0);
		poll_append_session(spa, 1);
		poll_append_session(spb, 0);
		poll_append_session(spb, 1);
	}
	
	append_session(&RtppGlobals.cfg, spa);

	vm_set_msg_param(OSAL_NULL, RtppGlobals.cfg.sessions_active, VM_PARAM_CONCURRENT);


	if (RtppGlobals.cfg.sessions_active > (RtppGlobals.cfg.nofile_limit.rlim_max * 80 / (100 * 4)) &&
	  RtppGlobals.cfg.nofile_limit_warned == 0) 
	{
		RtppGlobals.cfg.nofile_limit_warned = 1;
		 OSAL_trace(eRTPP, eWarn, "passed 80%% "
		  "threshold on the open file descriptors limit (%d), "
		  "consider increasing the limit using -L command line "
		  "option", (int)RtppGlobals.cfg.nofile_limit.rlim_max);
	}

	OSAL_trace(eRTPP, eInfo,
		"new session on port %d/%d created, "
	  "tag %s", lport, rport, uid);


	for(i=0; i<RtppGlobals.cfg.timeout_socket_num; i++)  {	
		cp = strchr(RtppGlobals.cfg.timeout_handler[i]->socket_name, ':');
		if(!strncmp(inet_ntoa((satosin(&raddr))->sin_addr), RtppGlobals.cfg.timeout_handler[i]->socket_name, 
			(int)(cp-RtppGlobals.cfg.timeout_handler[i]->socket_name)))
		{
			spa->timeout_data.handler = RtppGlobals.cfg.timeout_handler[i];
			OSAL_trace(eRTPP, eInfo, "setting notify timeout handler OK");				
			if (spa->timeout_data.notify_tag != OSAL_NULL) 
			{
				free(spa->timeout_data.notify_tag);
				spa->timeout_data.notify_tag = OSAL_NULL;
			}
			sprintf(notify_str, "M%s.0 %c %s %s\n", call_cookie, 't', argv[1], argv[2]);
			OSAL_trace(eRTPP, eInfo, "notify_tag=%s", notify_str);
			spa->timeout_data.notify_tag = strdup(notify_str);
			OSAL_trace(eRTPP, eInfo,
				"setting timeout notify_tag[%s] OK", spa->timeout_data.notify_tag);			
		}
	}
	if(i == RtppGlobals.cfg.timeout_socket_num)  {
		spa->timeout_data.handler = NULL;			
		OSAL_trace(eRTPP, eWarn, "timeout handle is NULL");
	}



	if (argv[1] != OSAL_NULL) {
		for(i=0; i<MAX_OPENSIP; i++) {		
			if(RtppGlobals.cfg.timeout_handler[i] != OSAL_NULL) {
				if (RtppGlobals.cfg.timeout_handler[i]->socket_name != OSAL_NULL)
				{
					if(strcmp(RtppGlobals.cfg.timeout_handler[i]->socket_name, argv[1]) == 0)
					{
						spa->timeout_data.handler = RtppGlobals.cfg.timeout_handler[i];

						if (spa->timeout_data.notify_tag != OSAL_NULL) 
						{
							free(spa->timeout_data.notify_tag);
							spa->timeout_data.notify_tag = OSAL_NULL;
						}
						sprintf(notify_str, "M%s.0 %c %s %s\n", call_cookie, 't', argv[1], argv[2]);
						OSAL_trace(eRTPP, eInfo, "notify_tag=%s", notify_str);
						spa->timeout_data.notify_tag = strdup(notify_str);
						OSAL_trace(eRTPP, eInfo,
							"setting notify[%s] timeout handler OK", spa->timeout_data.notify_tag);

						break;
					}
				}
			}
		}
	}
	else if (argv[1] == OSAL_NULL && spa->timeout_data.handler == OSAL_NULL) 
	{
		OSAL_trace(eRTPP, eError,
			"setting timeout handler error");
	}

	memcpy(spa->addr[1], ia[0], sizeof(struct sockaddr));
	memcpy(spa->rtcp->addr[1], ia[1], sizeof(struct sockaddr));
	memcpy(spa->addr[0], ia[2], sizeof(struct sockaddr));
	memcpy(spa->rtcp->addr[0], ia[3], sizeof(struct sockaddr));
	strcpy(spa->gw_ip, inet_ntoa(((struct sockaddr_in*)spa->addr[0])->sin_addr));
	spa->asymmetric[1] = spa->rtcp->asymmetric[1] = 0;
	spa->canupdate[1] = spa->rtcp->canupdate[1] = 1;

	for (i = 0; i < 4; i++)
		if (ia[i] != OSAL_NULL)
			osal_free(ia[i]);

	memset(content, 0, sizeof(content));
	sprintf(content, "%c 0 %d/%d", cmd ,lport, rport);
	rlen = sizeof(struct sockaddr_storage);
	m_cmd_repond(&RtppGlobals.cfg, fd, raddr, rlen, cookie, content);


	return OSAL_OK;	
}

	
OSAL_INT32 rtpp_delete_source(char *call_cookie, char *cookie, int fd, struct sockaddr_storage *raddr)
{
	int ret;
	struct rtpp_session *spa;
	int rlen;
	char content[8];
	char cmd = 'k';

	if(!call_cookie || !cookie ||!raddr)
		return OSAL_ERROR;

	spa = session_findfirst(&RtppGlobals.cfg, call_cookie);
	if(spa == OSAL_NULL){
		OSAL_trace(eRTPP, eError, "the cookie: %s hasn't exsited.", call_cookie);
		return OSAL_ERROR;
	}

	ret = handle_delete(&RtppGlobals.cfg, call_cookie, spa->from_tag, spa->to_tag, 0);
	if(ret < 0)
		OSAL_trace(eRTPP, eWarn, "the cookie: %s hasn't exsited.", call_cookie);		
	else
		OSAL_trace(eRTPP, eInfo, "del call_id[%s] ftag[%s] ttag[%s]", call_cookie, spa->from_tag, spa->to_tag);

	memset(content, 0, sizeof(content));
	sprintf(content, "%c 0", cmd);
	rlen = sizeof(struct sockaddr_storage);
	m_cmd_repond(&RtppGlobals.cfg, fd, raddr, rlen, cookie, content);

	return OSAL_OK;
}
#endif

OSAL_INT32 rtpp_add_participant(OSAL_CHAR *call_cookie, OSAL_msgHdr *pMsg)
{
	OSAL_CHAR keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;
	OSAL_INT32 i, j;
	struct participant_info_t *sp;
	OSAL_CHAR content[512];
	OSAL_CHAR *bak = content;
    OSAL_INT32 len = 0;
	OSAL_CHAR cmd = 'a';

	OSAL_INT32 argc;
	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_CHAR *cookie, *op, *tmp;
	OSAL_INT32 rtpp_index = 0;
	OSAL_INT32 link_flags = 0;
	OSAL_CHAR link_ip[RTPP_MAX_IP_LEN] = {0};
	OSAL_INT32 complete_flags = 0;
	OSAL_INT32 asym_flags = 0;

	if(!call_cookie || !pMsg)
		return OSAL_ERROR;
	
	OSAL_INT32 mod_id = pMsg->msgSubId;
	OSAL_INT32 fip = pMsg->param;
	OSAL_UINT16 fport = pMsg->param2;
	OSAL_CHAR *msg = (OSAL_CHAR  *)pMsg->pContent;
	OSAL_INT32 lenth = pMsg->contentLen;

	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, OSAL_strnLen(call_cookie, MAX_COOKIE_LEN));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_add_participant: hash key = %s", keyBuff);

	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(pHash)				
	{
		command_parse(msg,lenth,argv,&argc);
		
		if(argc < 3){
			OSAL_trace (eRTPP, eError, "err format %s",msg);
			return OSAL_ERROR;
		}else{
			cookie = argv[0];
			op = argv[1];
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
			
				default:
					OSAL_trace(eRTPP, eError, "unknown command option '%c'",*tmp);
					break;
			}
		}
		
		if(link_flags && (rtpp_index = check_link_addr(link_ip)) < 0){
			OSAL_trace(eRTPP, eError, "ip %s is not in this rtpp",link_ip);
			return OSAL_ERROR;
		}
	
		memset(content, 0, sizeof(content));
		len = sprintf(bak, "%c 0", cmd);
		bak += len;
		for(i=2;i<argc && argv[i];i++)
		{
			char *q = strrchr(argv[i],'@');
			char tmp[10] = {0};
			if(q){
				strncpy(tmp, argv[i], q-argv[i]);
				int num = atoi(tmp);
				q++;
				if(strlen(q) <= 0){
					OSAL_trace(eRTPP, eError, "uid is null.");
					return OSAL_ERROR;	
				}
				
				for(j=0;j<MAX_PARTICIPANT_NUM;j++)
				{
					if(pHash->participant[j].valid && (!strcmp(pHash->participant[j].uid, q))){
						OSAL_trace(eRTPP, eError, "participant %s has exsited", pHash->participant[j].uid);
						return OSAL_ERROR;
					}
				}
				sp = get_rtpp_conf_session(pHash);
				if (sp == OSAL_NULL) 
				{
					OSAL_trace(eRTPP, eError, "no enough session to allcate");
				    return OSAL_ERROR;
				}
				sp->valid = 1;
				sp->partid = num;
				strcpy(sp->uid, q);
				strcpy(sp->partid_uid, argv[i]);
				if(rtpp_mixer_selct_alloc_port(mod_id, rtpp_index, sp) < 0){
					OSAL_trace(eRTPP, eError, "allocat port err");
					return OSAL_ERROR;
				}				
				sp->ss = pHash;
				OSAL_trace(eRTPP, eDebug, "create participant %s, index is %d, fd is %d, rtcpfd is %d",
											sp->uid, sp->index,sp->p->fd,sp->p->rtcpfd);				
				len = sprintf(bak, " %d@%d", sp->partid, sp->p->port);
				bak += len;
			}		
		}
					
		m_cmd_repond(cookie, content, fip, fport);
	}else{
		OSAL_trace(eRTPP, eError, "this conference cookie:%s hasn't found.", keyBuff);
		return OSAL_ERROR;
	}

	return OSAL_OK;
}


/*
OSAL_INT32 rtpp_add_participant(char *call_cookie, char *cookie, int argc, char *argv[], struct sockaddr *laddr, int fd, struct sockaddr_storage *raddr)
{
	OSAL_CHAR	 keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;
	int i, j, rlen;
	struct participant_info_t *sp;
	int fds[2];
	char content[512];
	char *bak = content;
    int len = 0;
	char cmd = 'a';

	if(!call_cookie || !cookie || !raddr || argc < 2)
		return OSAL_ERROR;

	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, strlen(call_cookie));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_add_participant: hash key = %s", keyBuff);


	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(pHash)				
	{	
		memset(content, 0, sizeof(content));
		len = sprintf(bak, "%c 0", cmd);
		bak += len;
		for(i=0;i<argc && argv[i];i++)
		{
			char *q = strrchr(argv[i],'@');
			char tmp[10] = {0};
			if(q){
				strncpy(tmp, argv[i], q-argv[i]);
				int num = atoi(tmp);
				q++;
				if(strlen(q) <= 0){
					OSAL_trace(eRTPP, eError, "uid is null.");
					return OSAL_ERROR;	
				}
				
				for(j=0;j<MAX_PARTICIPANT_NUM;j++)
				{
					if(pHash->participant[j].valid && (!strcmp(pHash->participant[j].uid, q))){
						OSAL_trace(eRTPP, eError, "participant %s has exsited", pHash->participant[j].uid);
						return OSAL_ERROR;
					}
				}
				sp = get_rtpp_conf_session(pHash);
				if (sp == OSAL_NULL) 
				{
					OSAL_trace(eRTPP, eError, "no enough session to allcate");
				    return OSAL_ERROR;
				}
				sp->valid = 1;
				sp->partid = num;
				strcpy(sp->uid, q);
				strcpy(sp->partid_uid, argv[i]);
				if(rtpp_allocate_port(&sp->port, fds, laddr) < 0)
					OSAL_trace(eRTPP, eError, "allocat port err");
				sp->fd[0] = fds[0];
				sp->fd[1] = fds[1];
				if(poll_append_conf_session(pHash, sp->index, 0) < 0)
					OSAL_trace(eRTPP, eError, "poll session rtp fd err");					
				if(poll_append_conf_session(pHash, sp->index, 1) < 0)
					OSAL_trace(eRTPP, eError, "poll session rtcp fd err");

				
				OSAL_trace(eRTPP, eInfo, "add participant %s to conference", sp->uid);	
				len = sprintf(bak, " %d@%d", sp->partid, sp->port);
				bak += len;
			}		
		}
					
		rlen = sizeof(struct sockaddr_storage);
		m_cmd_repond(&RtppGlobals.cfg, fd, raddr, rlen, cookie, content);	
	}

	return OSAL_OK;
}
*/

OSAL_INT32 rtpp_delete_participant(OSAL_CHAR *call_cookie, OSAL_msgHdr *pMsg)
{
	OSAL_CHAR keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;
	OSAL_INT32 i, j;
	OSAL_CHAR content[512];
	OSAL_CHAR *bak = content;
	OSAL_INT32 len = 0;
	OSAL_CHAR cmd = 'd';

	OSAL_INT32 argc;
	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_CHAR *cookie;

	if(!call_cookie || !pMsg)
		return OSAL_ERROR;
	
	OSAL_INT32 mod_id = pMsg->msgSubId;
	OSAL_INT32 fip = pMsg->param;
	OSAL_UINT16 fport = pMsg->param2;
	OSAL_CHAR *msg = (OSAL_CHAR  *)pMsg->pContent;
	OSAL_INT32 lenth = pMsg->contentLen;


	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, OSAL_strnLen(call_cookie, MAX_COOKIE_LEN));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_delete_participant: hash key = %s", keyBuff);

	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(pHash)				
	{
		command_parse(msg,lenth,argv,&argc);
		
		if(argc < 3){
			OSAL_trace (eRTPP, eError, "err format %s",msg);
			return OSAL_ERROR;
		}else{
			cookie = argv[0];
		}		
		
		memset(content, 0, sizeof(content));
		len = sprintf(bak, "%c 0", cmd);
		bak += len;
	
		for(i=1;argc > 2 && i<argc-1 && argv[i+1];i++)
		{
			for(j=0;j<MAX_PARTICIPANT_NUM;j++)
			{
				if(pHash->participant[j].valid && (!strcmp(argv[i+1], pHash->participant[j].partid_uid))){
					OSAL_trace(eRTPP, eInfo, "delete participant %s", pHash->participant[j].uid);
					if(pHash->participant[j].pt[0] >= 0){
						pstatistics_t pstate;
						Mixer_get_statistics(pHash->inst, pHash->participant[j].id, &pstate);
						OSAL_trace(eRTPP, eDebug, "Mixer_get_statistics:  participant %s, mix_recv %d, rtpp_recv %d,  mix_send %d, rtpp_send %d", pHash->participant[j].uid, 
							pstate.packetsReceived, pHash->participant[j].packetsReceived, pstate.packetsSent, pHash->participant[j].packetsSent);
						if(Mixer_remove_participant(pHash->inst, pHash->participant[j].id) < 0){							
							OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
							return OSAL_ERROR;
						}
						OSAL_trace(eRTPP, eSys, "delete participant %s", pHash->participant[j].uid);
					}
					
					len = sprintf(bak, " %d@%d", pHash->participant[j].partid, pHash->participant[j].p->port);
					bak += len;	
					rtpp_mixer_disselct_free_port(mod_id,pHash->participant[j].p);
					put_rtpp_conf_session(pHash, &pHash->participant[j]);
				}
			}			
		}
	
		m_cmd_repond(cookie, content, fip, fport);
	}
	else{
		OSAL_trace(eRTPP, eError, "can't find the conference %s", keyBuff);
		return OSAL_ERROR;
	}

	return OSAL_OK;
}


/*
OSAL_INT32 rtpp_delete_participant(char *call_cookie, char *cookie, int argc, char *argv[], int fd, struct sockaddr_storage *raddr)
{
	OSAL_CHAR	 keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;
	int i, j;
	int rlen;
	char content[512];
	char *bak = content;
	int len = 0;
	char cmd = 'd';

	if(!call_cookie || !cookie || !raddr || argc < 2)
		return OSAL_ERROR;

	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, strlen(call_cookie));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_delete_participant: hash key = %s", keyBuff);

	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(pHash)				
	{	
		memset(content, 0, sizeof(content));
		len = sprintf(bak, "%c 0", cmd);
		bak += len;
	
		for(i=0;argc > 1 && i<argc-1 && argv[i+1];i++)
		{
			for(j=0;j<MAX_PARTICIPANT_NUM;j++)
			{
				if(pHash->participant[j].valid && (!strcmp(argv[i+1], pHash->participant[j].partid_uid))){
					OSAL_trace(eRTPP, eInfo, "delete participant %s", pHash->participant[j].uid);
					if(pHash->participant[j].pt >= 0){
						pstatistics_t pstate;
						Mixer_get_statistics(pHash->inst, pHash->participant[j].id, &pstate);
						OSAL_trace(eRTPP, eDebug, "Mixer_get_statistics:  participant %s, mix_recv %d, rtpp_recv %d,  mix_send %d, rtpp_send %d", pHash->participant[j].uid, 
							pstate.packetsReceived, pHash->participant[j].packetsReceived, pstate.packetsSent, pHash->participant[j].packetsSent);
						if(Mixer_remove_participant(pHash->inst, pHash->participant[j].id) < 0){							
							OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
							return OSAL_ERROR;
						}
					}
					
					len = sprintf(bak, " %d@%d", pHash->participant[j].partid, pHash->participant[j].port);
					bak += len;
					poll_remove_conf_session(pHash, j, 0);
					poll_remove_conf_session(pHash, j, 1);
					close(pHash->participant[j].fd[0]);
					close(pHash->participant[j].fd[1]);	
					put_rtpp_conf_session(pHash, &pHash->participant[j]);
				}
			}			
		}
	
		rlen = sizeof(struct sockaddr_storage);
		m_cmd_repond(&RtppGlobals.cfg, fd, raddr, rlen, cookie, content);
	}
	else{
		OSAL_trace(eRTPP, eError, "can't find the conference");
		return OSAL_ERROR;
	}

	return OSAL_OK;
}
*/


OSAL_INT32 rtpp_delete_conference(OSAL_CHAR *call_cookie, OSAL_CHAR *cookie, OSAL_msgHdr *pMsg)
{
	OSAL_CHAR keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;

	OSAL_INT32 j;
	OSAL_CHAR content[8];
	OSAL_CHAR cmd = 'D';

	if(!call_cookie || !pMsg)
		return OSAL_ERROR;
	
	OSAL_INT32 mod_id = pMsg->msgSubId;
	OSAL_INT32 fip = pMsg->param;
	OSAL_UINT16 fport = pMsg->param2;
	
	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, OSAL_strnLen(call_cookie, MAX_COOKIE_LEN));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_delete_conference: hash key = %s", keyBuff);

	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(pHash){
		OSAL_trace(eRTPP, eDebug, "pHash->inst = %p", pHash->inst);
		if(Mixer_delete_conference(pHash->inst) < 0){
			OSAL_trace(eRTPP, eError, "fail to remove mixer conference");
			return OSAL_ERROR;
		}
		OSAL_trace(eRTPP, eSys, "delete conference:%s", pHash->call_cookie);

		if(pHash->check_conf_media_timer != OSAL_INVALID_TIMER_ID){
			OSAL_trace(eRTPP, eInfo, "delete conf check media timer");
			OSAL_stimerStop(pHash->check_conf_media_timer);
			pHash->check_conf_media_timer = OSAL_INVALID_TIMER_ID;
		}

		rtpp_stop_conf_empty_time(pHash);
		
		for(j=0;j<MAX_PARTICIPANT_NUM;j++)
		{
			if(pHash->participant[j].valid){
				OSAL_trace(eRTPP, eInfo, "delete participant %s", pHash->participant[j].uid);
				rtpp_mixer_disselct_free_port(mod_id,pHash->participant[j].p);
				put_rtpp_conf_session(pHash, &pHash->participant[j]);			
			}
		}

		pthread_mutex_lock(&rtpp_conf_hashtable_lock);	
		OSAL_hashElemDelete(conferenceHashTable, keyBuff, pHash);
		pthread_mutex_unlock(&rtpp_conf_hashtable_lock);
		
		memset(content, 0, sizeof(content));
		sprintf(content, "%c 0", cmd);		
		m_cmd_repond (cookie, content, fip, fport);
				
	}else{
		OSAL_trace(eRTPP, eError, "can't find the conference cookie:%s", keyBuff);
		return OSAL_ERROR;
	}

	return OSAL_OK;

}

/*
OSAL_INT32 rtpp_delete_conference(char *call_cookie, char *cookie, int fd, struct sockaddr_storage *raddr)
{
	OSAL_CHAR	 keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;

	int j;
	int rlen;
	char content[8];
	char cmd = 'D';

	if(!call_cookie || !cookie ||!raddr)
		return OSAL_ERROR;

	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, strlen(call_cookie));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_delete_conference: hash key = %s", keyBuff);

	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(pHash){
		OSAL_trace(eRTPP, eDebug, "messi debug : pHash->inst = %p", pHash->inst);
		if(Mixer_delete_conference(pHash->inst) < 0){
			OSAL_trace(eRTPP, eError, "fail to remove mixer conference");
			return OSAL_ERROR;
		}

		for(j=0;j<MAX_PARTICIPANT_NUM;j++)
		{
			if(pHash->participant[j].valid){
				OSAL_trace(eRTPP, eInfo, "delete participant %s", pHash->participant[j].uid);
				poll_remove_conf_session(pHash, j, 0);
				poll_remove_conf_session(pHash, j, 1);
				close(pHash->participant[j].fd[0]);
				close(pHash->participant[j].fd[1]);
				put_rtpp_conf_session(pHash, &pHash->participant[j]);			
			}
		}
		if (pHash->timeout_data.notify_tag != OSAL_NULL) {
			free(pHash->timeout_data.notify_tag);
			pHash->timeout_data.notify_tag = OSAL_NULL;
		}	
		OSAL_hashElemDelete(conferenceHashTable, keyBuff, pHash);
		memset(content, 0, sizeof(content));
		sprintf(content, "%c 0", cmd);
		rlen = sizeof(struct sockaddr_storage);
		m_cmd_repond(&RtppGlobals.cfg, fd, raddr, rlen, cookie, content);		
	}else{
		OSAL_trace(eRTPP, eError, "can't find the conference cookie:%s", keyBuff);
		return OSAL_ERROR;
	}

	return OSAL_OK;
}
*/
	
OSAL_INT32 rtpp_record_pt_code(OSAL_CHAR *call_cookie, OSAL_msgHdr *pMsg)
{
	OSAL_CHAR keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;
	int i, j, k;
	char content[8];
	char cmd = 'n';
	int partid;
	mixer_participant_t mp;
	int pt_number = 0;
	OSAL_CHAR *pts[MAX_PT_NUM];

	OSAL_INT32 argc;
	OSAL_CHAR *argv[RTPP_MAX_ARGC_NUM];
	OSAL_CHAR *cookie;

	if(!call_cookie || !pMsg)
		return OSAL_ERROR;
	
	OSAL_INT32 fip = pMsg->param;
	OSAL_UINT16 fport = pMsg->param2;
	OSAL_CHAR *msg = (OSAL_CHAR  *)pMsg->pContent;
	OSAL_INT32 lenth = pMsg->contentLen;


	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, OSAL_strnLen(call_cookie, MAX_COOKIE_LEN));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_record_pt_code: hash key = %s", keyBuff);

	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);

	if(pHash)				
	{	
		command_parse(msg,lenth,argv,&argc);		
		if(argc < 3){
			OSAL_trace (eRTPP, eError, "err format %s",msg);
			return OSAL_ERROR;
		}else{
			cookie = argv[0];
		}	

		for(i=1;argc > 2 && i<argc-1 && argv[i+1];i++)
		{
			char *q = strrchr(argv[i+1],'@');
			char tmp[32] = {0};
			if(q){
				strncpy(tmp, argv[i+1], q-argv[i+1]);
				partid = atoi(tmp);	
				for(j=0;j<MAX_PARTICIPANT_NUM;j++)
				{
					if(pHash->participant[j].valid && (partid == pHash->participant[j].partid)){
						q++;
						if(q != OSAL_NULL){
							if(strchr(q,',') != NULL)
							{							
								get_pt_values(q,strlen(q),pts,&pt_number);
								if(pt_number < 1){
									OSAL_trace (eRTPP, eError, "no pt value");
									return OSAL_ERROR;
								}else{
									for(k=0;k<pt_number;k++){
										pHash->participant[j].pt[k] = (mixer_codec_type_t)atoi(pts[k]);
									}
								} 							
							}
							else{
								pt_number = 1;
								pHash->participant[j].pt[0] = (mixer_codec_type_t)atoi(q);
							}
						}else{
							OSAL_trace (eRTPP, eError, "no pt value");
							return OSAL_ERROR;
						}
						OSAL_trace (eRTPP, eDebug, "pt[0] is %d",pHash->participant[j].pt[0]);

						mp.m_pt = pHash->participant[j].pt[0];
						if(pHash->participant[j].mixed == 0){
							if((pHash->participant[j].id = Mixer_add_participant(pHash->inst, &mp)) < 0){
								OSAL_trace(eRTPP, eError, "fail to add mixer participant");
								return OSAL_ERROR;
							}
							pHash->participant[j].mixed = 1;
							OSAL_trace(eRTPP, eSys, "record pt:%d to participant %s, mix_id is %d, cookie is %s", pHash->participant[j].pt[0], pHash->participant[j].uid, pHash->participant[j].id, pHash->call_cookie);
							mixer_codec_list_t codeclist;
							memset(&codeclist, 0, sizeof(mixer_codec_list_t));
							codeclist.num = pt_number;
							for(k=0;k<pt_number;k++)
								codeclist.ptlist[k] = pHash->participant[j].pt[k];
							Mixer_set_codeclist(pHash->inst,pHash->participant[j].id,&codeclist);
							break;
						}else{
							if(Mixer_remove_participant(pHash->inst, pHash->participant[j].id) < 0){							
								OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
								return OSAL_ERROR;
							}
							if((pHash->participant[j].id = Mixer_add_participant(pHash->inst, &mp)) < 0){
								OSAL_trace(eRTPP, eError, "fail to add mixer participant");
								return OSAL_ERROR;
							}
							OSAL_trace(eRTPP, eSys, "update pt:%d to participant %s, mix_id is %d, cookie is %s", pHash->participant[j].pt[0], pHash->participant[j].uid, pHash->participant[j].id, pHash->call_cookie);
							mixer_codec_list_t codeclist;
							memset(&codeclist, 0, sizeof(mixer_codec_list_t));
							codeclist.num = pt_number;
							for(k=0;k<pt_number;k++)
								codeclist.ptlist[k] = pHash->participant[j].pt[k];
							Mixer_set_codeclist(pHash->inst,pHash->participant[j].id,&codeclist);

							break;						
						}
					}
				}
				if(j == MAX_PARTICIPANT_NUM){
					OSAL_trace(eRTPP, eError, "can't find the participant");
					return OSAL_ERROR;
				}
				
			}		
		}

		memset(content, 0, sizeof(content));
		sprintf(content, "%c 0", cmd);		
		m_cmd_repond (cookie, content, fip, fport);
	}
	else{
		OSAL_trace(eRTPP, eError, "can't find the conference");
		return OSAL_ERROR;
	}

	return OSAL_OK;
}


/*
OSAL_INT32 rtpp_record_pt_code(char *call_cookie, char *cookie, int argc, char *argv[], int fd, struct sockaddr_storage *raddr)
{
	OSAL_CHAR	 keyBuff[MAX_COOKIE_LEN];
	struct conference_info_t *pHash = NULL;
	int i, j;
	int rlen;
	char content[8];
	char cmd = 'n';
	int partid;
	mixer_participant_t mp;

	if(!call_cookie || !cookie || !raddr || argc < 2)
		return OSAL_ERROR;

	memset(keyBuff, 0, sizeof(keyBuff));				
	strncpy(keyBuff, call_cookie, strlen(call_cookie));
	keyBuff[MAX_COOKIE_LEN-1] = '\0';
	OSAL_trace(eRTPP, eInfo, "rtpp_record_pt_code: hash key = %s", keyBuff);

	pHash = (struct conference_info_t *)OSAL_hashElemFind(conferenceHashTable, keyBuff);
	OSAL_trace(eRTPP, eDebug, "messi debug 0");

	if(pHash)				
	{
		OSAL_trace(eRTPP, eDebug, "messi debug 1");
	
		for(i=0;argc > 1 && i<argc-1 && argv[i+1];i++)
		{
			OSAL_trace(eRTPP, eDebug, "messi debug 2, loop %d", i);		
			char *q = strrchr(argv[i+1],'@');
			char tmp[32] = {0};
			OSAL_trace(eRTPP, eDebug, "messi debug 3, loop %d", i);					
			if(q){
				strncpy(tmp, argv[i+1], q-argv[i+1]);
				partid = atoi(tmp);	
				OSAL_trace(eRTPP, eDebug, "messi debug 4, loop %d", i);	
				for(j=0;j<MAX_PARTICIPANT_NUM;j++)
				{
					if(pHash->participant[j].valid && (partid == pHash->participant[j].partid)){
						OSAL_trace(eRTPP, eDebug, "messi debug 5, loop %d:%d", i, j);	
						q++;
						pHash->participant[j].pt = (mixer_codec_type_t)atoi(q);
						mp.m_pt = pHash->participant[j].pt;
						if(pHash->participant[j].mixed == 0){
							OSAL_trace(eRTPP, eDebug, "messi debug 6, loop %d:%d", i, j);	
							OSAL_trace(eRTPP, eDebug, "messi debug 6, pHash->inst addr is %p, pt is %d", pHash->inst, mp.m_pt);	
							if((pHash->participant[j].id = Mixer_add_participant(pHash->inst, &mp)) < 0){
								OSAL_trace(eRTPP, eError, "fail to add mixer participant");
								return OSAL_ERROR;
							}
							pHash->participant[j].mixed = 1;
							OSAL_trace(eRTPP, eInfo, "record pt:%d to participant %s, mix_id is %d", pHash->participant[j].pt, pHash->participant[j].uid, pHash->participant[j].id);
							break;
						}else{
							OSAL_trace(eRTPP, eDebug, "messi debug 7, loop %d:%d", i, j);	
							if(Mixer_remove_participant(pHash->inst, pHash->participant[j].id) < 0){							
								OSAL_trace(eRTPP, eError, "fail to remove mixer participant");
								return OSAL_ERROR;
							}
							OSAL_trace(eRTPP, eDebug, "messi debug 8, loop %d:%d", i, j);								
							if((pHash->participant[j].id = Mixer_add_participant(pHash->inst, &mp)) < 0){
								OSAL_trace(eRTPP, eError, "fail to add mixer participant");
								return OSAL_ERROR;
							}
							OSAL_trace(eRTPP, eInfo, "update pt:%d to participant %s, mix_id is %d", pHash->participant[j].pt, pHash->participant[j].uid, pHash->participant[j].id);
							break;						
						}
					}
				}
				OSAL_trace(eRTPP, eDebug, "messi debug 9");					
				if(j == MAX_PARTICIPANT_NUM){
					OSAL_trace(eRTPP, eError, "can't find the participant");
					return OSAL_ERROR;
				}
				
			}		
		}
		OSAL_trace(eRTPP, eDebug, "messi debug 10"); 	

		memset(content, 0, sizeof(content));
		sprintf(content, "%c 0", cmd);		
		rlen = sizeof(struct sockaddr_storage);
		m_cmd_repond(&RtppGlobals.cfg, fd, raddr, rlen, cookie, content);
	}
	else{
		OSAL_trace(eRTPP, eError, "can't find the conference");
		return OSAL_ERROR;
	}

	return OSAL_OK;
}
*/


