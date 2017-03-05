#ifndef _RA_NB_H_
#define _RA_NB_H_

#include <string>
#include <memory>
#include <map>
#include <sstream>
#include <cstdio>
#include <algorithm>
#include <sys/time.h>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <vector>


#define ICMP_PK_LEN 56
#define RA_ICMP_ECHOREPLY  0
#define RA_ICMP_ECHO 8
#define RA_NBR_UNREACH 3000000   //us

class  AttributesEntry
{
	public:


	inline
	AttributesEntry()
	{}

	
	inline
	AttributesEntry(const std::string& name, 
	const std::string& value)
	: fName(name), fValue(value)
	{fintValue = -1;}

	inline
	AttributesEntry(const std::string& name, 
	int value)
	: fName(name),fintValue(value)
	{fValue = "";}

	inline
	AttributesEntry(const AttributesEntry& entry)
	{ operator=(entry); }

	inline
	~AttributesEntry()
	{}
	
	AttributesEntry& 
	operator= (const AttributesEntry& entry);
	
	inline std::string
	getName() 						const
	{ return fName; }

	inline std::string
	getValue() 						const
	{ return fValue; }

	
	inline int
	getIntegerValue() 		const
	{return fintValue;}

	inline std::string::size_type
	length() 						const
	{ return fValue.length(); }

	inline bool 
	isEmpty() 						const
	{ return (0 == length()); }


	private:  
	std::string fName;		
	std::string fValue;	
	int fintValue;
};

struct PingCfg{
	OSAL_INT32 calcIntv;
	OSAL_INT32 pingIntv;
	OSAL_INT32 cost_thred;
};

typedef struct seqmap_value
{
    OSAL_INT32    hostNbr;
    OSAL_INT32    pingCnt;
    struct timeval  pingTs;

} SEQMAP_VALUE;


class HostEntry
{
	public:
		HostEntry(const std::string &addrStr)
			: host(addrStr),lossRate(0.0),avgRtt(0.0),status(0)
		{
			 ipAddr = inet_addr(host.c_str());
			 num_recv = 0;
			 num_recv_i = 0;
			 total_time = 0;
			 total_time_i = 0;
			 num_sent = 0;
			 num_sent_i = 0;
			 is_need_report = OSAL_FALSE;
		}

		~HostEntry()
		{

		}
		inline OSAL_INT32 getIpAddr() const {return ipAddr;}
		void resetCalc_i();
		void calc_i();
		inline std::string getHost() const {return host;}
		inline OSAL_UINT8 getStatus() const {return status;}
		inline OSAL_UINT32 getLossRate() const {return lossRate;}
		inline OSAL_UINT32 getAvgRtt() const {return avgRtt;}

	private:
		int calc_cost(int delay, int lost);

	public:
		struct timeval       last_send_time;     /* time of last packet sent */
		long                  num_sent;           /* number of ping packets sent */
		long                  num_recv;           /* number of pings received (duplicates ignored) */
		long                  total_time;         /* sum of response times */
		long                   max_reply;        /* longest response time */
     	long                   min_reply;        /* shortest response time */
		/* _i -> splits (reset on every report interval) */
		long                  num_sent_i;         /* number of ping packets sent */
		long                  num_recv_i;         /* number of pings received */
		long                  total_time_i;       /* sum of response times */
		long                   max_reply_i;        /* longest response time */
        long                   min_reply_i;        /* shortest response time */

	OSAL_BOOL		is_need_report;
	OSAL_BOOL	admin_disconn;  //administrator set the host is disconnecting status, just for test. 

	OSAL_UINT32		last_cost;
        
	private:
		std::string 		  host;
		OSAL_INT32            ipAddr;
		OSAL_UINT32           lossRate;
		OSAL_UINT32           avgRtt;
		OSAL_UINT8            status;//0:dead,1:active
};


class RaPing
{
	public:
		RaPing(const std::string &addrStr)
		: sock(-1),sockBak(-1),agentAddr(addrStr),agentAddrBak(""),icmpSeq(0)
		{
			ident = getpid() & 0xFFFF;
		}
		~RaPing()
		{

		}
		OSAL_INT32 createPingSocket();
		OSAL_INT32 createBakPingSocket();
		bool parseJsonNbList(const std::string &input);
		bool parseByJson(const std::string &input);
		void addNbrHost(const std::string &host);
		void addNbrHostBak(const std::string &host);
		OSAL_UINT16 calcSum(OSAL_UINT16 *buffer, OSAL_UINT32 length);
		long timevalDiff( struct timeval *a, struct timeval *b );
		void txPingPkt(HostEntry &hostAddr,OSAL_INT32 fd);
		void startTxPingTimer();
		void stopTxPingTimer() {OSAL_stimerStop(txPingTimer);};
		void startCalcPingTimer();
		void stopCalcPingTimer() {OSAL_stimerStop(calcPingTimer);};
		void txPingTimeOut();
		void calcTimeOut();
		void set_nbr_admin_disconn(OSAL_INT8 *nbr_ip, OSAL_INT32 status);
		void rxPingPkt(OSAL_INT32 fd);
		void showHost();
		inline OSAL_INT32 getSockId() const {return sock;}
		inline OSAL_INT32 getSockIdBak() const {return sockBak;}
		inline void setSockId(OSAL_INT32 fd) {sock = fd;}
		inline std::string getSelfAddr() const {return agentAddr;}
		inline void clearNbrHost() {nbrHost.clear();}
		inline void clearNbrHostBak() {nbrHostBak.clear();}
		inline void setAgentBakAddr(std::string &addr) {agentAddrBak = addr;}
	public:
		typedef std::map<OSAL_INT32,HostEntry> HostEntryMap;
		typedef std::map<OSAL_INT32,SEQMAP_VALUE> SeqValueMap;		
		struct PingCfg pingCfg;
		SeqValueMap seqMap;
	private:
		OSAL_INT32	sock;	
		OSAL_INT32	sockBak;
		std::string agentAddr;
		std::string agentAddrBak;
		OSAL_UINT16	ident;
		HostEntryMap nbrHost;
		HostEntryMap nbrHostBak;
		OSAL_UINT32 icmpSeq;
		OSAL_TIMER_ID calcPingTimer;
		OSAL_TIMER_ID txPingTimer;
};

struct rtEntry
{
	std::string ipAddr;
	OSAL_INT32  port;
	OSAL_UINT32	connCount;
};
class Routers
{
	public:
		Routers()
		{

		}

		~Routers()
		{

		}
		OSAL_INT32 parseConf(std::string &listStr);
		inline void addRte(rtEntry &rte) {rtList.push_back(rte);}
		void delRte(std::string &ipaddr);
		rtEntry getToConnRte();
		void increRteConnCount(rtEntry &rte);
		std::string getRtesStr();
	private:
		std::string curRtAddr;
		OSAL_INT32  curRtPort;
		std::vector<rtEntry> rtList;
};
#endif


