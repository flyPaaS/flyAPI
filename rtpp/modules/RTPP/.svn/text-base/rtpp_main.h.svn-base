#ifndef _RTPP_MAIN__H_
#define _RTPP_MAIN__H_

#ifdef __cplusplus
extern "C" {
#endif  /*__cplusplus */
#include "OSAL.h"
#include "rtpp_common.h"
/* add by liujianfeng for packet loss rate statistics errors on 2016-1-20 15:56:23 */
#include "rtpp_session.h"
/* add by liujianfeng end */

#define RTPP_LABEL_COMMAND 				"RTPP_COMMAND_SOCK"
#define RTPP_LABEL_HOST_IP 				"RTPP_HOST_IP"
#define RTPP_LABEL_RTPC_IP 				"RTPP_RTPC_IP"
#define RTPP_LABEL_TTL_MODE 	 		"RTPP_TTL_MODE"
#define RTPP_LABEL_TIMEOUT_LEN 			"RTPP_TIMEOUT_LEN"
#define RTPP_LABEL_RECORD_DIR 			"RTPP_RECORD_DIR"
#define RTPP_LABEL_VM_SERVER_MODE 		"RTPP_VM_SERVER_MODE"
#define RTPP_LABEL_LOSS_RC_MODE 		"RTPP_LOSS_RC_MODE"
#define RTPP_LABEL_JT_FLAG 				"RTPP_JT_FLAG"
#define MEDIA_CHECK_TIME_LEN 			3 //√Î
#define RTP_VERSION_3 0xC0
#define RTP_VERSION_2 0x80



enum 
{
	RTPP_LEFT_AUDIO = 1,
	RTPP_RIGHT_AUDIO = 2,
	RTPP_LEFT_VIDEO = 4,
	RTPP_RIGHT_VIDEO = 8,
};

#define is_audio(a) ((a&0x3)!=0)
#define is_video(a) ((a&0xc)!=0)

#define REV(a) case a:ret=#a; break

static inline const OSAL_CHAR *porttype2str (OSAL_INT32 st)
{
	const OSAL_CHAR *ret;

	switch (st) {
		REV (RTPP_LEFT_AUDIO);
		REV (RTPP_RIGHT_AUDIO);
		REV (RTPP_LEFT_VIDEO);
		REV (RTPP_RIGHT_VIDEO);
	default:
		ret = "Unknown Port type";
		break;
	}
	return ret;
}
enum {
	RTCP_PT_SR = 200,
	RTCP_PT_RR = 201,
	RTCP_PT_BYE = 203,
	RTCP_PT_FEC = 204,
	RTCP_PT_FEC_RSP = 205,
};

typedef struct
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
        unsigned char  rc           :5;
        unsigned char padding       :1;
	 unsigned char ver           :2;
#elif __BYTE_ORDER == __BIG_ENDIAN
        unsigned char ver           :2;
        unsigned char padding       :1;
        unsigned char rc           :5;
#endif		
        unsigned char pt;
	short length;
	unsigned int	ssrc;
}__attribute__ ((packed))rtcphdr_t;

typedef struct TagRtppTestT {
	rtpp_session_t ss[2];
    OSAL_TIMER_ID t;
}RtppTestT;

typedef struct _stat_
{
	OSAL_UINT64 rxCounts;
	OSAL_UINT64 rxBytes;
	OSAL_UINT64 txCounts;
	OSAL_UINT64 txBytes;
	OSAL_INT32  concurrency;
	OSAL_INT32  ipConcurrency;
}RttpPktStat;

typedef struct _cfg_ {
	OSAL_INT32      controlfd;
	OSAL_INT16      ttlmode;
	OSAL_INT32      timeout;
	OSAL_INT16      rtpcnum;
	OSAL_CHAR		record_dir[RTPP_MAX_RECORD_DIR];
	OSAL_CHAR       rtpcip[RTPP_MAX_RTPC_NUM][RTPP_MAX_IP_LEN];
	OSAL_INT32      rtpc[RTPP_MAX_RTPC_NUM];
	OSAL_INT16      localipnum;
	OSAL_CHAR       command_socket[RTPP_COMMAND_SOCKET_LEN];
	OSAL_CHAR       localip[RTPP_MAX_LOCAL_NUM][RTPP_MAX_IP_LEN];
    RtppTestT         htest;
    OSAL_CHAR 		rc_flag;
	OSAL_CHAR 		jt_flag;
	OSAL_INT16      historypercent;
	RttpPktStat     stats_;
	OSAL_TIMER_ID   stat_timer;
}RtppGlobalsT;

extern RtppGlobalsT RtppGlobals;
extern pthread_mutex_t rtpp_conf_hashtable_lock;

OSAL_INT32 rtpp_recv_rtcp_fec(port_info_t *refer, OSAL_CHAR *buf, OSAL_INT32 len);
OSAL_INT32 rtpp_send_rtcp_fec(port_info_t *refer);
OSAL_INT32 rtpp_resend_rtcp_fec(port_info_t *refer);
OSAL_INT32 rtpp_send_rtcp_fec_rsp(port_info_t *refer,OSAL_UINT32 ssrc);

int rtpp_media_end(rtpp_session_t *ss);

extern OSAL_INT32 rtpp_init (void);

extern OSAL_INT32 rtpp_main(OSAL_msgHdr *pMsg);

extern void rtpp_end (void);

OSAL_INT32 rtpp_us_proc (OSAL_INT32 iFec,OSAL_INT32 iModel,OSAL_CHAR* remoteIp,OSAL_INT32 remotePort);

#ifdef __cplusplus
}
#endif

#endif
