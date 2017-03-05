#ifndef __RTPP_NOTIFY_H__
#define __RTPP_NOTIFY_H__

#include <string>
#include <memory>
#include <map>
//#include <mysql/mysql.h>

#include <sstream>
#include <cstdio>
#include <algorithm>
#include <sys/time.h>
#include <cstring>
#include <iostream>
//#include <unistd.h>
#include <algorithm>

#include <json/json.h>

#include "../RTPP/rtpp_common.h"

#define MD5SECR "Flypaas123"

enum NOTIFY_MSG_TYPE
{
	NOTIFY_MEDIA_OUT = 4,
	NOTIFY_LOG = 5,
	NOTIFY_BILL = 6,
};


typedef struct _rtppcon_t_ {
	OSAL_INT32      fd;
	OSAL_INT32      ip;
	struct _rtppcon_t_  * pre;
	struct _rtppcon_t_  * next;
}rtppcon_t;

typedef struct _media_notify_t_ {
	OSAL_INT32      num;
	rtppcon_t       *first;
}media_notify_t;

typedef struct
{
	OSAL_UINT8 msg_type;
	OSAL_UINT8 body_type;
	OSAL_UINT16 sn;
	OSAL_UINT16 body_len;
	OSAL_CHAR md5[16];
	OSAL_INT8 body[0];
}__attribute__((packed))notify_msg;


#endif
