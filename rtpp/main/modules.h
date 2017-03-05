#ifndef __RTPP_MODULES_H__
#define __RTPP_MODULES_H__

#include "rtpp_main.h"
#include "ping_main.h"

extern OSAL_INT32 rtpp_init (void);
extern OSAL_INT32 rtpp_main(OSAL_msgHdr *pMsg);
extern void rtpp_end(void);

extern OSAL_INT32 rtpp_work_init (void);
extern OSAL_INT32 rtpp_work_main(OSAL_msgHdr *pMsg);
extern void rtpp_work_end(void);


extern OSAL_INT32 ping_init (void);
extern OSAL_INT32 ping_main(OSAL_msgHdr *pMsg);
extern void ping_end(void);

extern OSAL_INT32 notify_init (void);
extern OSAL_INT32 notify_main(OSAL_msgHdr *pMsg);
extern void notify_end(void);

extern OSAL_INT32 ra_init (void);
extern OSAL_INT32 ra_main(OSAL_msgHdr *pMsg);
extern void ra_end(void);


#ifdef INCLUDE_MON
extern OSAL_INT32 monitor_init();
extern OSAL_INT32	monitor_main(OSAL_msgHdr *pMsg);
extern void monitor_end(void);

extern RtppGlobalsT RtppGlobals;
extern PingGlobalsT PingGlobalData;
#endif
#endif

