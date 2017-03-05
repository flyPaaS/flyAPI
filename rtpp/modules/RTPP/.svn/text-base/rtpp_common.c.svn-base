#include "rtpp_main.h"
#include "rtpp_common.h"
extern RtppGlobalsT RtppGlobals;

OSAL_INT32 rtpp_create_sock(OSAL_CHAR *ip, OSAL_UINT16 port,OSAL_INT32 tos,OSAL_INT32 sock_type,OSAL_INT32 proto)
{
    struct sockaddr_in serv_addr;
    OSAL_INT32  buffSize = 4096 * 1024 * 2;
    OSAL_INT32  sock = -1;
    OSAL_INT32  optval;
    OSAL_INT32  flags;
 
    if ((sock = socket(AF_INET, sock_type, proto)) < 0)
    {
        OSAL_trace(eRTPP, eError,"socket err: %s.", strerror(errno));
        exit(-1);
    }

	
	optval=1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR ,(void*)&optval, sizeof(optval)) == -1)
	{
		OSAL_trace(eRTPP, eError,"setsockopt SO_REUSEADDR err: %s.", strerror(errno));
        return -1;
	}
	
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize)) < 0) 
    {
		OSAL_trace(eRTPP, eError,"setsockopt SO_RCVBUF err: %s.", strerror(errno));
        close(sock);
        return -1;
    }
	
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffSize, sizeof(buffSize)) < 0) 
    {
		OSAL_trace(eRTPP, eError,"setsockopt SO_RCVBUF err: %s.", strerror(errno));
        close(sock);
        return -1;
    }

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_port        = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr(ip);

    if (bind(sock,(struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        OSAL_trace(eRTPP, eWarn,"bind ip:%s,port:%d err: %s.", ip,port,strerror(errno));
        close(sock);
        return -1;
    }

 	if (tos && setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1)
		OSAL_trace(eRTPP, eError, "unable to set TOS to %d", tos);


	flags = fcntl(sock, F_GETFL);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    //OSAL_trace(eRTPP, eSys,"create %s socket OK!ip:%s,port:%d.",sock_type == SOCK_STREAM ? "tcp":"udp",ip,port);

    return sock;
}

OSAL_INT32 rtpp_udp_send(OSAL_INT32 sock,OSAL_CHAR *pbuf,OSAL_INT32 len,OSAL_INT32 ipvalue,OSAL_INT32 port)
{
	struct sockaddr_in to_rtpp;
	OSAL_INT32 ret;
	
	to_rtpp.sin_family = AF_INET;
	to_rtpp.sin_port	= htons((short)port);
	to_rtpp.sin_addr.s_addr = ipvalue;
	
    ret = sendto(sock, pbuf, len, 0, (struct sockaddr *)&to_rtpp, sizeof(struct sockaddr));
    if (ret < 0)
    {
        OSAL_trace(eRTPP, eError,"sending fail, ip = 0x%x port = %d, error(%s)", 
            ipvalue, port, strerror(errno));
        return -1;
    }

    if (len != ret)
    {
        OSAL_trace(eRTPP, eError,"send fail, len = %u not send.", len - ret);
		return -1;
    }


	return 0;
}
OSAL_INT32 rtpp_udp_trans(OSAL_INT32 sock,OSAL_CHAR *pbuf,OSAL_INT32 len,OSAL_INT32 ipvalue,OSAL_INT32 port)
{
	struct sockaddr_in to_rtpp;
	OSAL_INT32 ret;
	
	to_rtpp.sin_family = AF_INET;
	to_rtpp.sin_port	= port;
	to_rtpp.sin_addr.s_addr = ipvalue;
	
    ret = sendto(sock, pbuf, len, 0, (struct sockaddr *)&to_rtpp, sizeof(struct sockaddr));
    if (ret < 0)
    {
        OSAL_trace(eRTPP, eError,"sending fail, ip = 0x%x port = %d, error(%s)", 
            ipvalue, port, strerror(errno));
        return -1;
    }

    if (len != ret)
    {
        OSAL_trace(eRTPP, eError,"send fail, len = %u not send.", len - ret);
		return -1;
    }
	
	RtppGlobals.stats_.txCounts++;
	RtppGlobals.stats_.txBytes += len;
	return 0;
}

OSAL_INT32 get_rand_num()
{	
	//srand(time(0));
	return rand()%30000;
}


