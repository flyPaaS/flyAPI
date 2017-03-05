//#include "stdafx.h"
#include "rtp_to_prtp.h"
#include <string.h>

#include "OSAL.h"


unsigned char aucCIDToPTHash[] = 
{
	18, 13, 98, 99, 105, 101, 106, 107, 127, 50, 110, 111, 112, 113, 114, 115 
};


enum {
	false = 0,
	true
};
static void AssignUWord16ToBuffer(unsigned char* dataBuffer, unsigned short value) {
#if defined(WEBRTC_LITTLE_ENDIAN)
  //dataBuffer[0] = static_cast<unsigned char>(value >> 8);
  //dataBuffer[1] = static_cast<unsigned char>(value);
   dataBuffer[0] = (unsigned char)(value >> 8);
   dataBuffer[1] = (unsigned char)(value);
#else
  //unsigned short* ptr = reinterpret_cast<unsigned short*>(dataBuffer);
  unsigned short* ptr = (unsigned short*)(dataBuffer);
  ptr[0] = value;
#endif
}

static void AssignUWord32ToBuffer(unsigned char* dataBuffer, unsigned int value) {
#if defined(WEBRTC_LITTLE_ENDIAN)
  dataBuffer[0] = (unsigned char)(value >> 24);
  dataBuffer[1] = (unsigned char)(value >> 16);
  dataBuffer[2] = (unsigned char)(value >> 8);
  dataBuffer[3] = (unsigned char)(value);
#else
  unsigned int* ptr = (unsigned short*)(dataBuffer);
  ptr[0] = value;
#endif
}


bool CIDToPT(const enum ePRTP_CID_type eCID, unsigned char *pcPayloadType)
{
	if (eCID > NUM_CID_TYPE)
	{
		return false;
	}
	
	*pcPayloadType = aucCIDToPTHash[eCID];
	return true;
}

bool PTToCID(const unsigned char payloadType, enum ePRTP_CID_type *peCID)
{
	int i;
	for ( i = 0; i < NUM_CID_TYPE; i++)
	{
		if (payloadType == aucCIDToPTHash[i])
		{
			*peCID = (enum ePRTP_CID_type)i;
			return true;
		}
	}
    return false;
}

int RTPToPRTP(st_PRTPP_chan* pstPRTPPChan,
						unsigned char* dataBuffer,
			            int *psPayloadLength)

{
	enum ePRTP_CID_type eCID;
	unsigned short usSq;
	unsigned int uiTs;
    unsigned char payloadType;
	unsigned char acPRTPDDataBuf[MAX_TMP_BUFF];	
    char cVersion;
	int	iPayloadSize = *psPayloadLength - LENGTH_RTP_HEADER;

    unsigned char* ptr = &dataBuffer[4];
	payloadType = dataBuffer[1] & 0x7f;
	usSq = (dataBuffer[2] << 8) + dataBuffer[3];
	uiTs = *ptr++ << 24;
	uiTs += *ptr++ << 16;
	uiTs += *ptr++ << 8;
	uiTs += *ptr++;

	cVersion = dataBuffer[0] & 0xc0;    // version 3 for private rtp
	
	if (cVersion == (char)0xc0)
	{
		return 0;		// private rtp
	}

	//return if rtcp packet
	if ((unsigned char)0x81 == dataBuffer[1])
	{
		return -1;
	}
	
	if (!PTToCID(payloadType, &eCID))
	{
		return -1;
	}

    acPRTPDDataBuf[0] = (unsigned char)(0xc0);            // version 3 for private rtp
    acPRTPDDataBuf[0] |= (unsigned char)((char)eCID << 2);

	if (!pstPRTPPChan->bInitFlag)
	{
	    pstPRTPPChan->uiBaseTs = uiTs;
		pstPRTPPChan->uiTs = 0;
		pstPRTPPChan->bInitFlag = true;
	}
	else
	{
		if (uiTs > pstPRTPPChan->uiBaseTs)
		{
			pstPRTPPChan->uiTs = (uiTs - pstPRTPPChan->uiBaseTs)/LENGTH_MIN_PACKET;
		}
		else
		{
			pstPRTPPChan->uiTs = 0;
		    pstPRTPPChan->uiBaseTs = uiTs;
		}
	}

    acPRTPDDataBuf[0] |= (unsigned char)((pstPRTPPChan->uiSq >> 10) & 0x3);
	acPRTPDDataBuf[1] = (unsigned char)((pstPRTPPChan->uiSq >> 2) & 0xff);
	AssignUWord16ToBuffer(acPRTPDDataBuf+2, (unsigned short)(pstPRTPPChan->uiTs));
	acPRTPDDataBuf[2] &= 0x3f;
	acPRTPDDataBuf[2] |= (unsigned char)((pstPRTPPChan->uiSq & 0x3)<< 0x6);

	if(eCID == ePRTP_CID_G729)
	{
		int count = iPayloadSize/20;
		pstPRTPPChan->uiSq +=count;	
	}
	else
		pstPRTPPChan->uiSq++;		

	memcpy(acPRTPDDataBuf+LENGTH_PRTP_HEADER, dataBuffer+LENGTH_RTP_HEADER, iPayloadSize);
	memcpy(dataBuffer, acPRTPDDataBuf, iPayloadSize+LENGTH_PRTP_HEADER);
	*psPayloadLength -= LENGTH_RTP_HEADER - LENGTH_PRTP_HEADER;

    return LENGTH_PRTP_HEADER;
}
	
void PRTPToRTP(st_PRTPD_chan* pstPRTPDChan,
			unsigned char* dataBuffer,
            int *psPayloadLength)
{
	enum ePRTP_CID_type eCID;
	unsigned short usSq;
	unsigned int uiTs;
    unsigned char payloadType;
	unsigned char acPRTPDDataBuf[MAX_TMP_BUFF];
	char cVersion;
	int	iPayloadSize = *psPayloadLength - LENGTH_PRTP_HEADER;
	
	if(pstPRTPDChan->needParser == 0)
	{
		if(iPayloadSize < 0)
		{
			pstPRTPDChan->needParser = 0;
			return;
		}
		eCID = (enum ePRTP_CID_type)((dataBuffer[0] >> 2) & 0xf);
		usSq = ((dataBuffer[0] & 0x3) << 10) | (dataBuffer[1] << 2) | (dataBuffer[2] >> 6);
		uiTs = ((dataBuffer[2] << 8 | dataBuffer[3]) &0x3fff) * LENGTH_MIN_PACKET;

		cVersion = dataBuffer[0] & 0xc0;    // version 3 for private rtp
		if (cVersion != (char)0xc0)
		{
			pstPRTPDChan->needParser = 0;
			return;		//Not PRTP, should be RTP or rtcp;
		}
		
		if (!CIDToPT(eCID, &payloadType))
		{
			pstPRTPDChan->needParser = 0;
			return;	
		}

		acPRTPDDataBuf[0] = (unsigned char)(0x80);            // version 2
		acPRTPDDataBuf[1] = payloadType;
		AssignUWord16ToBuffer(acPRTPDDataBuf+2, usSq);
		AssignUWord32ToBuffer(acPRTPDDataBuf+4, uiTs);
		AssignUWord32ToBuffer(acPRTPDDataBuf+8, pstPRTPDChan->uiSSRC);
	 	if(eCID == ePRTP_CID_G729)
		{
			pstPRTPDChan->payload = payloadType;
			if(iPayloadSize > 20 && (iPayloadSize % 20 == 0))
			{
				pstPRTPDChan->index= 1;
				pstPRTPDChan->seq = usSq+1;
				pstPRTPDChan->ts = uiTs +160;// 2 means 160
				pstPRTPDChan->leftLen = iPayloadSize -20;
				pstPRTPDChan->needParser = 1;
				memcpy(pstPRTPDChan->payloadBuffer,dataBuffer+LENGTH_PRTP_HEADER,iPayloadSize);
				memcpy(acPRTPDDataBuf+LENGTH_RTP_HEADER, dataBuffer+LENGTH_PRTP_HEADER, 20);
				memcpy(dataBuffer, acPRTPDDataBuf, 20+LENGTH_RTP_HEADER);
				*psPayloadLength = 20+LENGTH_RTP_HEADER;
			}
			else
			{
				pstPRTPDChan->needParser = 0;
				memcpy(acPRTPDDataBuf+LENGTH_RTP_HEADER, dataBuffer+LENGTH_PRTP_HEADER, iPayloadSize);
				memcpy(dataBuffer, acPRTPDDataBuf, iPayloadSize+LENGTH_RTP_HEADER);
				*psPayloadLength = iPayloadSize +LENGTH_RTP_HEADER;
				
			}
		}
		else
		{
			memcpy(acPRTPDDataBuf+LENGTH_RTP_HEADER, dataBuffer+LENGTH_PRTP_HEADER, iPayloadSize);
			memcpy(dataBuffer, acPRTPDDataBuf, iPayloadSize+LENGTH_RTP_HEADER);
			*psPayloadLength += LENGTH_RTP_HEADER - LENGTH_PRTP_HEADER;
			pstPRTPDChan->needParser = 0;
		}
	}
	else if(pstPRTPDChan->needParser == 1)
	{
		acPRTPDDataBuf[0] = (unsigned char)(0x80);            // version 2
		acPRTPDDataBuf[1] = pstPRTPDChan->payload;
		AssignUWord16ToBuffer(acPRTPDDataBuf+2, pstPRTPDChan->seq);
		AssignUWord32ToBuffer(acPRTPDDataBuf+4, pstPRTPDChan->ts);
		AssignUWord32ToBuffer(acPRTPDDataBuf+8, pstPRTPDChan->uiSSRC);
		if(pstPRTPDChan->leftLen  > 20 && (pstPRTPDChan->leftLen % 20 == 0))
		{
			pstPRTPDChan->seq++;
			pstPRTPDChan->ts+=160;
			pstPRTPDChan->leftLen -= 20;
			pstPRTPDChan->needParser = 1;
			memcpy(acPRTPDDataBuf+LENGTH_RTP_HEADER, pstPRTPDChan->payloadBuffer+pstPRTPDChan->index*20, 20);
			memcpy(dataBuffer, acPRTPDDataBuf, 20+LENGTH_RTP_HEADER);
			*psPayloadLength = 20+LENGTH_RTP_HEADER;
			pstPRTPDChan->index++;
		}
		else
		{
			pstPRTPDChan->needParser = 0;
			memcpy(acPRTPDDataBuf+LENGTH_RTP_HEADER, pstPRTPDChan->payloadBuffer+pstPRTPDChan->index*20, pstPRTPDChan->leftLen);
			memcpy(dataBuffer, acPRTPDDataBuf, pstPRTPDChan->leftLen+LENGTH_RTP_HEADER);
			*psPayloadLength = pstPRTPDChan->leftLen +LENGTH_RTP_HEADER;
		}
	}
}
