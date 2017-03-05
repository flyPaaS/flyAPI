#ifndef _RTPP_UTIL_H_
#define _RTPP_UTIL_H_

#include "rtpp_common.h"
#include "rtpp_session.h"


typedef struct table_info_t{
	alloc_info_t *p;
	pthread_mutex_t lock;
	alloc_info_t *free;
	alloc_info_t *free_tail;
	OSAL_INT32   used;
}table_info_t;

extern table_info_t table[RTPP_MAX_LOCAL_NUM];

OSAL_INT32 init_port_table();
OSAL_INT32 init_controlfd();
alloc_info_t *rtpp_alloc_port(OSAL_INT32 index);
OSAL_INT32 rtpp_free_port(alloc_info_t *pinfo);
OSAL_INT32 rtpp_disselct_free_port(OSAL_INT32 mod_id,alloc_info_t *dealloc);
OSAL_INT32 rtpp_disselct_port(OSAL_INT32 mod_id,alloc_info_t *dealloc);
OSAL_INT32 rtpp_pop_port(OSAL_INT32 branche,OSAL_INT32 port_index, OSAL_INT32 mod_id,OSAL_CHAR index,OSAL_INT32 ip,OSAL_INT32 aport,
		OSAL_INT32 vport,OSAL_INT32 video,OSAL_INT32 asy,OSAL_INT32 mix,OSAL_INT32 fec_mode, rtpp_session_t *ss);
OSAL_INT32 command_parse(OSAL_CHAR *buf,OSAL_INT32 len,OSAL_CHAR *argv[],OSAL_INT32 *argc);
OSAL_INT32 check_ip_list(OSAL_CHAR *list,OSAL_CHAR deli);
OSAL_INT32 rtpp_ip_check(OSAL_INT32 ip);
OSAL_INT32 get_callid (OSAL_CHAR *buf,OSAL_CHAR *callid);
OSAL_INT32 rtpp_reply_err (OSAL_CHAR *cookie,OSAL_INT32 errcode,OSAL_INT32 ipvalue,OSAL_UINT16 port);
OSAL_INT32 rtpp_reply_port (OSAL_CHAR *cookie, OSAL_INT8 branche, OSAL_INT32 port_index, OSAL_UINT16 aport,OSAL_UINT16 vport,OSAL_INT32 ipvalue,OSAL_UINT16 port);
OSAL_INT32 rtpp_reply_ok (OSAL_CHAR *cookie,OSAL_INT32 ipvalue,OSAL_UINT16 port);
OSAL_INT32 rtpp_d_reply_ok (OSAL_CHAR *cookie, OSAL_INT32 branche, OSAL_INT32 port_index,OSAL_INT32 ipvalue,OSAL_UINT16 port);
//modify for transparent index to rtpp 20160512
OSAL_INT32 rtpp_d_reply_s_ok (OSAL_CHAR *cookie,OSAL_INT32 branche, OSAL_INT32 port_index, OSAL_INT32 ipvalue,OSAL_UINT16 port, double left_loss, double right_loss, 
	OSAL_INT32 left_pt, OSAL_INT32 right_pt,OSAL_CHAR *left_mgw, OSAL_CHAR *right_mgw, OSAL_UINT32 lrr, OSAL_UINT32 rrr, OSAL_UINT32 lrs, OSAL_UINT32 rrs,OSAL_CHAR *transmsg,
	OSAL_UINT32 rx_bytes,OSAL_UINT32 tx_bytes);
//modify end
OSAL_CHAR *get_link_addr(OSAL_CHAR *s,OSAL_CHAR *l);
OSAL_INT32 check_link_addr(OSAL_CHAR *link_ip);
OSAL_INT32 get_record_callid(const OSAL_CHAR *str, OSAL_CHAR **record_callid, OSAL_CHAR **end);
OSAL_INT32 get_calleeMideaInfo(OSAL_CHAR *msg, int msg_len,OSAL_CHAR *calleeMediaIp,OSAL_CHAR *calleeMediaPort,OSAL_CHAR *calleeMediaVPort);

void rtpp_update_left_aport(OSAL_INT32 ip,OSAL_INT32 port_index, OSAL_INT32 aport,OSAL_INT32 asy,rtpp_session_t* ss);
void rtpp_update_right_aport(OSAL_INT32 ip,OSAL_INT32 port_index,OSAL_INT32 aport,OSAL_INT32 asy,rtpp_session_t* ss);
void rtpp_update_left_vport(OSAL_INT32 ip,OSAL_INT32 port_index,OSAL_INT32 vport,OSAL_INT32 asy,rtpp_session_t* ss);
void rtpp_update_right_vport(OSAL_INT32 ip,OSAL_INT32 port_index,OSAL_INT32 vport,OSAL_INT32 asy,rtpp_session_t* ss);
#endif
