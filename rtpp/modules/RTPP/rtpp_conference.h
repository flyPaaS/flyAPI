#ifndef _RTPP_CONFERENCE_H_
#define _RTPP_CONFERENCE_H_


#include "rtpp_session.h"
#include "rtpp_mixer.h"
#include "rtpp_util.h"
#include "rtpp_common.h"

#define MAX_UID_LEN 64
#define MAX_COOKIE_LEN 128
#define MAX_PARTICIPANT_NUM 16
#define MAX_CONFERENCE_NUM 500
#define MAX_PT_NUM 20

struct participant_info_t
{
	OSAL_INT32 id;
	mixer_codec_type_t  pt[MAX_PT_NUM];
	OSAL_INT32  partid;
	OSAL_CHAR uid[MAX_UID_LEN];
	OSAL_CHAR partid_uid[MAX_UID_LEN+5];
	struct sockaddr addr[2];
	struct sockaddr *laddr;
	OSAL_INT32 index;	
	OSAL_INT32 ttl;
	OSAL_INT32 next_free;
	//OSAL_INT32 port;
	//OSAL_INT32 fd[2];
	OSAL_INT32 valid;
	OSAL_INT32 mixed;
	OSAL_INT32 packetsSent;
	OSAL_INT32 packetsReceived;
	alloc_info_t *p;
	struct conference_info_t *ss;
};


struct conference_info_t
{
	time_t ttl;
	void *inst;
	OSAL_CHAR call_cookie[MAX_COOKIE_LEN];
	struct participant_info_t participant[MAX_PARTICIPANT_NUM];
	OSAL_CHAR  notify[RTPP_MAX_NOTIFY_LEN];
	OSAL_INT32	from_ip;
	OSAL_INT32 mod_id;
	OSAL_INT32	session_free_list;
	OSAL_INT32 session_active;
	OSAL_INT32 has_added;
	OSAL_TIMER_ID check_conf_media_timer;
	OSAL_TIMER_ID empty_conftimer;
	pthread_mutex_t conflock;
};


struct trans_info_t
{
	OSAL_INT32 index;
	media_type_t type;
	struct conference_info_t *party;
};


typedef struct str_t
{
	OSAL_INT32 len;
	void* buf;
}str_t;


typedef struct udp_data_t
{
	OSAL_INT32 type;//RTP/RTCP	
	OSAL_INT32 channelid;
	OSAL_INT32 mcid;
	str_t data;
}udp_data_t;



OSAL_INT32 m_cmd_repond_err (OSAL_CHAR *cookie,OSAL_INT32 errcode, OSAL_CHAR cmd, OSAL_INT32 argc, OSAL_CHAR *argv[], OSAL_INT32 ipvalue,OSAL_UINT16 port);
OSAL_INT32 rtpp_start_conf_media_time (struct conference_info_t *conf);
OSAL_INT32 rtpp_check_conf_media_timeout (struct conference_info_t * ss);
OSAL_INT32 rtpp_del_empty_conf (struct conference_info_t * ss);
void rtpp_mixer_trace_log_cb(OSAL_INT32 level, const OSAL_CHAR* logbuf, OSAL_INT32 loglen);
OSAL_INT32 rtpp_mixer_send_media_cb(void* us_handle, OSAL_INT32 m_cnid, const media_data_t* m_data);
void rtpp_mixer_recv_mix_media(OSAL_msgHdr *pMsg);
OSAL_INT32 rtpp_creat_conference(OSAL_CHAR *call_cookie, OSAL_msgHdr *pMsg);
OSAL_INT32 rtpp_add_participant(OSAL_CHAR *call_cookie, OSAL_msgHdr *pMsg);
OSAL_INT32 rtpp_delete_participant(OSAL_CHAR *call_cookie, OSAL_msgHdr *pMsg);
OSAL_INT32 rtpp_delete_conference(OSAL_CHAR *call_cookie, OSAL_CHAR *cookie, OSAL_msgHdr *pMsg);
OSAL_INT32 rtpp_record_pt_code(OSAL_CHAR *call_cookie, OSAL_msgHdr *pMsg);






OSAL_INT32 rtpp_convert_to_conference(OSAL_CHAR *call_cookie, OSAL_msgHdr *pMsg);


/*
void *check_conference_ttl(OSAL_HHASH hHash, void  *elem, void *param);

void rtpp_mixer_trace_log_cb(int level, const char* logbuf, int loglen);

void rtpp_mixer_recv_mix_media(OSAL_msgHdr *pMsg);

void rtpp_mixer_send_media_cb(void* us_handle, int m_cnid, const media_data_t* m_data);

void m_cmd_repond_err(struct cfg *cf, int fd, struct sockaddr_storage *raddr, socklen_t rlen, char *cookie, char *cmd, int argc, char *argv[]);

OSAL_INT32 rtpp_creat_conference(char *call_cookie, char *cookie, int argc, char *argv[], struct sockaddr *laddr, int fd, struct sockaddr_storage *raddr);


OSAL_INT32 rtpp_allocate_port(int *port, int *fds, struct sockaddr *laddr);

OSAL_INT32 rtpp_allocate_source(char *call_cookie, char *cookie, int argc, char *argv[], struct sockaddr *laddr, int fd, struct sockaddr_storage *raddr);
	
OSAL_INT32 rtpp_delete_source(char *call_cookie, char *cookie, int fd, struct sockaddr_storage *raddr);

OSAL_INT32 rtpp_add_participant(char *call_cookie, char *cookie, int argc, char *argv[], struct sockaddr *laddr, int fd, struct sockaddr_storage *raddr);
	
OSAL_INT32 rtpp_delete_participant(char *call_cookie, char *cookie, int argc, char *argv[], int fd, struct sockaddr_storage *raddr);
	
OSAL_INT32 rtpp_delete_conference(char *call_cookie, char *cookie, int fd, struct sockaddr_storage *raddr);
	
OSAL_INT32 rtpp_record_pt_code(char *call_cookie, char *cookie, int argc, char *argv[], int fd, struct sockaddr_storage *raddr);
*/


#endif
