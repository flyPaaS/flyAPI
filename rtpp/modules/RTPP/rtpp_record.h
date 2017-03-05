#ifndef _RTPP_RECORD_H_
#define _RTPP_RECORD_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "rtpp_session.h"


#define	DLT_NULL	0
#define	PCAP_MAGIC	0xa1b2c3d4
#define	PCAP_VER_MAJR	2
#define	PCAP_VER_MINR	4


#define MAX_PATH_LEN 300
#define RC_SLOT_NUM 200

typedef struct rtpp_record_channel
{
    char rpath[MAX_PATH_LEN + 1];  
    int fd;
    char rbuf[4096];
    int rbuf_len;
}rtpp_record_channel_t;

typedef struct
{
    unsigned short plen;	/* Length of following RTP/RTCP packet */
}__attribute__ ((packed))pkt_hdr_record_t;

typedef struct
{
    unsigned char codec_pt;	/*record file payload type */
	char reserve[127];
}__attribute__ ((packed))file_hdr_record_t;

struct rc_pktnode
{
	OSAL_UINT32 len;
	OSAL_CHAR buf[0];
};

struct rc_node{
	void *data;
	OSAL_CHAR used_flag;
	OSAL_UINT16 seq;
};

typedef enum {
	chan_pre = 1,
	chan_after,
}chan_types;

#define REV(a) case a:ret=#a; break

static inline const OSAL_CHAR *chan_types2str (OSAL_UINT8 st)
{
	const OSAL_CHAR *ret;

	switch (st) {
		REV (chan_pre);
		REV (chan_after);
	default:
		ret = "Unknown chan type";
		break;
	}
	return ret;
}


struct rc_ch{
	OSAL_INT32 fd;
	struct rc_node rcn[RC_SLOT_NUM];
	OSAL_UINT8 start_p;
	OSAL_UINT8 end_p;	
	OSAL_UINT16 start_seq;
	OSAL_UINT16 end_seq;
	OSAL_UINT8 chan_type; //chan_types
};

struct rc_ctr
{
	struct rc_ch pre;
	struct rc_ch after;
	OSAL_CHAR wr_times;
	OSAL_CHAR start_flag;
	OSAL_CHAR init_flag;	
	OSAL_CHAR rpath[MAX_PATH_LEN + 1]; 
};


struct _rtpp_session_;
struct _port_info_t_;

void *ropen(char *dir, struct _rtpp_session_ *sp, char *rname, int side);
void rwrite(rtpp_record_channel_t *rrc, char *buf, unsigned short len);
void rclose(rtpp_record_channel_t *rrc);
void rtpp_handle_record(OSAL_CHAR *record_dir, OSAL_INT32 side, OSAL_CHAR *record_name, struct _rtpp_session_ *sp);
void rtpp_check_record(OSAL_CHAR *record_dir, OSAL_INT32 record_flag, OSAL_CHAR *record_name, struct _rtpp_session_ *ss);

void rtpp_rc_init(struct _port_info_t_ *refer);

void rtpp_rc_push(struct _port_info_t_ *refer,struct rc_ch *rch,OSAL_UINT8 *buf, OSAL_INT32 len,OSAL_UINT16 seq);

void rtpp_rc_control(struct _port_info_t_ *refer,OSAL_UINT16 lost);


/* Global PCAP Header */
typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

/* PCAP Packet Header */
typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

/*
 * Recorded data header
 */
struct pkt_hdr_pcap {
    pcaprec_hdr_t pcaprec_hdr;
    uint32_t family;
    struct ip iphdr;
    struct udphdr udphdr;
} __attribute__((__packed__));


#endif
