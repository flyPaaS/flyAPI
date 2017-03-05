#ifndef _RTPP_SESSION_H_
#define _RTPP_SESSION_H_

#include "rtpp_common.h"
#include "rtpp_record.h"
#include "rtp_to_prtp.h"


#define RTPP_SESSION_MAX_NUM 3000

#define RTPP_HASH_MAX_LENTH  1021
#define RTPP_NULL_ID  -1

#define REALLOST_SLOT_NUM		100
#define JT_SLOT_NUM 200
#define JT_SNAP_NUM 200

#define SSRC_SNAP_NUM 10

#define SEQ_MAP_LEN			250

#define FLAG_STR_FEC					"RTPP_FEC"
#define FLAG_STR_REALTIME				"RTPP_NONE"
#define FLAG_STR_RTCP					"RTPP_RTCP"

#define FLAG_STR_RTCP_REPORT				"REALLOST_GT5_RTPP_RTCP"
#define FLAG_STR_FEC_REPORT				"REALLOST_GT5_RTPP_FEC"
#define FLAG_STR_REALTIME_REPORT		"REALLOST_GT5_RTPP_NONE"
#define FLAG_STR_SNAP_REPORT		"REALLOST_SNAPSHOOT_RTPP"
#define FLAG_STR_JITTER_REPORT		"REALJITTER_RTPP"
#define FLAG_STR_SNAP_JITTER		"REALJITTER_SNAPSHOOT_RTPP"
#define FLAG_STR_SNAP_SSRC		"SSRC_SNAPSHOOT_RTPP"


#define SPECACLL_STR_CALLID         "1111111111111%d2222222222222%d"
#define SPECCALL_STR_CALLER         "1111111111111%d"
#define SPECCALL_STR_CALLEE         "2222222222222%d"
#define SPECCALL_STR_COOKIE         "U127.0.0.1@00%d@1111111111.00%d"

#define Init_TestInstance_Timer	   99
enum 
{
	RTPP_DIR_LEFT,
	RTPP_DIR_RIGHT,
	RTPP_DIR_MAX
};

typedef struct alloc_info_t{
	OSAL_INT32 fd;
	OSAL_UINT16 port;
	OSAL_INT16 index;
	OSAL_INT32 rtcpfd;
	struct alloc_info_t *next; 
}alloc_info_t;

typedef struct __lostrate_node__
{
	time_t  ts;
	unsigned short lost;
}lostrate_node_t;

typedef struct __realtime_lost__
{
	OSAL_BOOL   is_first_packet_received;
	OSAL_UINT64	last_calc_systs;  //system timestamp
	OSAL_UINT32 last_calc_ts;
	OSAL_UINT32 last_calc_seq;
	OSAL_UINT32 last_calc_ssrc;
	OSAL_UINT16 current_seq;
	OSAL_UINT32 rcv_count;
	lostrate_node_t  rt_lostrate[REALLOST_SLOT_NUM];  //lostrate * 10000, 0.01% as 1
	OSAL_UINT32 rt_index;
	OSAL_UINT32 calc_count;
	OSAL_UINT32 total_lost;
	OSAL_CHAR  seq_map[SEQ_MAP_LEN];
}realtime_lost_entry;

typedef enum {
	RealTime_Lost,
	RealTime_Lost_Fec,
	RealTime_Lost_Rtcp
}calc_type;

typedef enum {
	CALC_TIME,
	CALC_SSRC,
	CALC_LOOP,
	CALC_FJITERR,
	CALC_BJITERR,
}calc_reason;

#define REV(a) case a:ret=#a; break

static inline const OSAL_CHAR *calureason2str (OSAL_UINT8 st)
{
	const OSAL_CHAR *ret;

	switch (st) {
		REV (CALC_TIME);
		REV (CALC_SSRC);
		REV (CALC_LOOP);
		REV (CALC_FJITERR);
		REV (CALC_BJITERR);
	default:
		ret = "Unknown calc type";
		break;
	}
	return ret;
}


typedef struct _packet_info_t_ {
	unsigned char  ver;
	unsigned char  pt;
	OSAL_UINT16 seq;
	OSAL_UINT32 ts;
	OSAL_UINT32 ssrc;
	OSAL_UINT8   *buf;
	OSAL_UINT32   len;
	OSAL_UINT64 recv_time;/*单位是毫秒用于计算一般延时*/
	OSAL_UINT64 recv_utime;/*单位是微秒用于计算抖动*/
	unsigned char rsd_flag;
}packet_info_t;

struct jt_node
{
	OSAL_CHAR flag;
	double rx_time;
	double tx_time;
};

struct jt_ret{
	time_t  ts;
	double jitter;
};

struct jt_stat{
	struct jt_ret snap[JT_SNAP_NUM];
	struct jt_node slot[JT_SLOT_NUM];
	OSAL_UINT32 jt_offset;
	OSAL_UINT32 list_c;
	OSAL_UINT32 total;
};

typedef struct _port_ssrc_t_ {
	time_t      ts;
	time_t      te;
	OSAL_UINT32 ssrc;
	OSAL_UINT32 fip;
	OSAL_UINT16 fport;
	OSAL_UINT32 recv;
}ssrc_t;

typedef struct _port_info_t_ {
	OSAL_INT8  asym;
	OSAL_INT8  va_flag;
	OSAL_INT32 fip;    //network byte; example: 4555 ->[55555 rtpp 56789]->1345, fip is 4555
	OSAL_UINT16 fport; //network byte
	OSAL_UINT16 frtcpport;   //network byte
	OSAL_INT32	private_rtp;
	OSAL_INT32 pt;
	OSAL_INT32 id;
	OSAL_INT8 no_media_notify_flag;
	OSAL_INT32 mixed;
	OSAL_BOOL  is_alloc_sk;
	alloc_info_t *p;
	alloc_info_t *pbak;
	struct rtpp_record_channel *rrcs;
	struct _rtpp_session_ *ss;
	struct _port_info_t_ *trans;
	OSAL_UINT8	fec_mode;   //编码1 解码0
	OSAL_UINT8	fec_send;
	OSAL_UINT32 fec_peer_lost;//0~~10000
	OSAL_UINT32 fec_local_lost; //0~~10000
	OSAL_UINT32 fec_local_last_lost; //0~~10000
	OSAL_UINT32 fec_local_smooth_lost;
	OSAL_UINT32 fec_local_last_smooth_lost;
	OSAL_UINT64 fec_syn_ts;//FEC RTCP包同步时间默认值为第一个包的时间
	OSAL_UINT64 fec_ack_ts;//FEC RTCP包确认时间默认值为第一个包的时间
	OSAL_BOOL   fec_rtcp_snd;
	OSAL_BOOL   fec_rtcp_resnd;
	OSAL_BOOL   recv_lost_calc_finish;
	OSAL_UINT8  calu_value; //CALC_TIME
	realtime_lost_entry realtime_lost;
	realtime_lost_entry realtime_lost_fec;
	realtime_lost_entry realtime_lost_rtcp;
	OSAL_INT32 discardRtpInteval;
	OSAL_INT32 discardNumber;
	OSAL_INT32 Rtpindex;
	OSAL_INT32 current_discardRtpInteval;
	OSAL_INT32 current_discardNumber;

	OSAL_UINT16 chc;
	OSAL_UINT64 media_last_active;
	OSAL_UINT64 first_media_time;
	
	OSAL_BOOL   is_first_packet_received;
	OSAL_UINT32 recv_packets;
	OSAL_UINT32 send_packets;
	OSAL_UINT64 recv_bytes;
	OSAL_UINT64 send_bytes;

	/*当前处理的包的包头信息*/
	packet_info_t packet;

	union{
		st_PRTPD_chan p2schan;
		st_PRTPP_chan s2pchan;
	};

	OSAL_BOOL  ssrc_ful;
	OSAL_INT32 ssrc_num;
	ssrc_t ssrc[SSRC_SNAP_NUM];

	OSAL_INT32 fec_rec;
	struct rc_ctr *rcctr;
	OSAL_UINT32 jt_calc;
	struct jt_stat jt;
}port_info_t;

typedef struct _rtpp_port_t_ {
	port_info_t   audio[PORT_NUM_MAX];
	port_info_t   video[PORT_NUM_MAX];
}branche_info_t;

typedef struct _rtpp_session_
{
	OSAL_INT32 id;
	void *inst;
	
	//rtpp_port_t left;
	//rtpp_port_t right;
	
	branche_info_t branches[RTPP_BRANCHE_MAX];
	#define left branches[RTPP_BRANCHE_LEFT]
	#define right  branches[RTPP_BRANCHE_RIGHT]
	OSAL_INT8 branche_is_initialized[RTPP_BRANCHE_MAX];
	
	OSAL_INT32 next_id;
	OSAL_INT32 inuse;
	OSAL_INT32 mod_id;
	OSAL_INT32 vflag;  // vedio flag
	OSAL_INT32 tsc_flag;  // transcoding flag
	OSAL_INT32 record_flag;  // record flag	
	OSAL_BOOL carry_option_b; //'b' option flag, use to compatible with old rtpc version
	pthread_mutex_t splock;

	OSAL_INT32  from_ip;
	OSAL_CHAR  cookie[RTPP_MAX_COOKIE_LEN];
	OSAL_CHAR  call_id[RTPP_MAX_CALLID_LEN];
    	OSAL_CHAR  f_tag[RTPP_MAX_TAG_LEN];                         /*add for test*/
    	OSAL_CHAR  to_tag[RTPP_MAX_TAG_LEN];
	OSAL_CHAR  notify[RTPP_MAX_NOTIFY_LEN];
	OSAL_INT32    finish;

	OSAL_INT32    ttlmode; //0: all   1: side
	OSAL_INT32    timeout;
	OSAL_INT32 private_rtp; 
	OSAL_INT32 fec_flag;
	void 	*fec_inst;
	OSAL_TIMER_ID mtime;
	time_t create_time;
	time_t connect_time;

	OSAL_CHAR release_reason;

	//added by tien @20170214
	struct timeval startTime;
	struct timeval endTime;

	struct _rtpp_session_ *pre;
	struct _rtpp_session_ *next; 
}rtpp_session_t;

typedef struct _rtpp_ss_pool_
{
	rtpp_session_t *malloc;
	OSAL_INT32 free_sid;
	OSAL_INT32 free_eid;
	pthread_mutex_t lock;
}rtpp_ss_pool_t;

typedef struct _rtpp_hash_info_
{
	pthread_mutex_t lock;
	rtpp_session_t *first;
}rtpp_hash_info;

typedef struct _rtpp_hash_table_
{
	atomic_t used;
	rtpp_hash_info enter[RTPP_HASH_MAX_LENTH];
}rtpp_hash_table;

extern rtpp_ss_pool_t rtpp_ss_pool;
extern rtpp_hash_table rtpp_hash_tbl;

OSAL_INT32 rtpp_session_init(void);
OSAL_UINT32 rtpp_hashvalue(const OSAL_CHAR *s);
OSAL_INT32 rtpp_free_session(rtpp_session_t *session);
OSAL_INT32 rtpp_free_old_session(rtpp_session_t *ss);
OSAL_INT32 rtpp_get_call_count();
rtpp_session_t* rtpp_new_session(OSAL_CHAR *s);
OSAL_INT32 rtpp_find_session(OSAL_CHAR *callid, rtpp_session_t ** ss);

#endif
