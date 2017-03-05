#ifndef _RTP_TO_PRTP_H_
#define _RTP_TO_PRTP_H_

#define NUM_CID_TYPE		16
#define LENGTH_PRTP_HEADER	4
#define LENGTH_RTP_HEADER	12
#define LENGTH_MIN_PACKET	80
#define WEBRTC_LITTLE_ENDIAN

#define MAX_TMP_BUFF 2048

typedef  int  bool;

enum ePRTP_CID_type
{
	ePRTP_CID_G729,		// 18

	// Comfort noise for three different sampling frequencies.
	ePRTP_CID_CN_13,  	// 13
	ePRTP_CID_CN_98,  	// 98
	ePRTP_CID_CN_99,  	// 99

	ePRTP_CID_Silk,		// 105 for old version
    ePRTP_CID_telephone_event, // 101
	ePRTP_CID_SILK_106,	//106 for new version
	ePRTP_CID_AMR_107,	//107

	ePRTP_CID_FEC_127,	//127 for fec
	ePRTP_CID_SILKWB_50,//50 for silkwb
	ePRTP_CID_EXP_110,	//110 for expand
	ePRTP_CID_EXP_111,	//111 for expand
	ePRTP_CID_EXP_112,	//112 for expand
	ePRTP_CID_EXP_113,	//113 for expand
	ePRTP_CID_EXP_114,	//114 for expand
	ePRTP_CID_EXP_115,	//115 for expand
	
};

typedef struct tag_stuct_PRTPP_chan
{
	bool bInitFlag;				//the flag of initiation
    unsigned int uiBaseTs;			//base timestamp
    unsigned int uiSq;			//squence number
    unsigned int uiTs;			//timestamp
}st_PRTPP_chan;

typedef struct tag_stuct_PRTPD_chan
{
	int uiSSRC;//ssrc the rtp use
	int needParser;//indicate we need continue parser the same prtp packet
	int seq;//the seq next rtp packet use
	int ts;//the time stamp next rtp use
	unsigned char payload;//pt 
	int leftLen;//left payload lenth not deal
	unsigned char payloadBuffer[MAX_TMP_BUFF];//save the payload
	int index;//how many 20ms we have parser
}st_PRTPD_chan;


typedef struct
{
        short Ver           :2;
        short Padding       :1;
        short Ext           :1;
        short CSRCCnt       :4;
        short m             :1;
        short PT            :7;

        short  sn;              /*RTP sequence number*/
        unsigned int   ts;              /*RPT Time stamp*/
        unsigned int   SSRC;            /*RTP synchronization source identifier*/
}__attribute__ ((packed))RTP_HDR;


bool CIDToPT(const enum ePRTP_CID_type eCID, unsigned char *pcPayloadType);
bool PTToCID(const unsigned char payloadType, enum ePRTP_CID_type *peCID);
int RTPToPRTP(st_PRTPP_chan* pstPRTPPChan,
						unsigned char* dataBuffer,
			            int *psPayloadLength);
void PRTPToRTP(st_PRTPD_chan* pstPRTPDChan,
			unsigned char* dataBuffer,
            int *psPayloadLength);

#endif
