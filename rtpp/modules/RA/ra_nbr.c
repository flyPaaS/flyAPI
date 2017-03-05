#include "ra.h"
#include "ra_nbr.h"
#include "ra_config.h"

RaPing *pingHd = NULL;
static Routers raRts;

void HostEntry::resetCalc_i()
{
	num_sent_i = 0;
	num_recv_i = 0;
	total_time_i = 0;
	max_reply_i = 0;
	min_reply_i = 0;
	is_need_report = OSAL_FALSE;
}


int HostEntry::calc_cost(int delay, int lost)
{
	int a = 70;
	float delay_f;

	//把微妙转换成毫秒
	delay_f = delay * 1.0 / 1000;

	if (delay_f > 500.0)  delay_f = 500.0;
	if (lost > 100) lost = 100;
	/*
	 *  公式：cost = delay*10*(100-a)/100+lost*5*10*a/100
	 *  delay:单位为毫秒，如延迟为100ms，则delay为100，delay范围为[0~500];
	 *  lost :百分值，比如丢包为5%，则lost为5,lost范围为[0~100]；
	 *  [0 ~ 600) 非常好
	 *  [600 ~ 1200) 好
	 *  [1200 ~ 1800)  良好
	 *  [1800 ~ 2400)  一般
	 *  [2400 ~ 3000)  差
	 *  [3000 ~ 5000]  很差
	 */
	return (delay_f * 10 * (100 - a) / 100 + lost * 5 * 10 * a / 100);
	
}

void HostEntry::calc_i()
{
	OSAL_UINT32 curr_cost;
	
	if(num_recv_i == 0){
		/*
		*邻居不可达
		*/
		avgRtt = RA_NBR_UNREACH;
		status = 0;
	}else{
		avgRtt = total_time_i/num_recv_i;
		status = 1;
	}
	OSAL_trace(eRA, eDebug,"host:%s,total_time_i:%ul,num_recv_i:%d,num_sent_i:%d",this->getHost().c_str(),total_time_i,num_recv_i,num_sent_i);	
	if(num_sent_i)
		lossRate = (num_sent_i - num_recv_i)/num_sent_i * 100;
	else{
		avgRtt = RA_NBR_UNREACH;
		lossRate = 100;
	}

	#if 1  //test code 
	if (OSAL_TRUE == admin_disconn) {
		avgRtt = RA_NBR_UNREACH;
		lossRate = 100;
		status = 0;	
	}	
	#endif 

	curr_cost = calc_cost(avgRtt, lossRate);

	if (abs(curr_cost - last_cost) > pingHd->pingCfg.cost_thred) {
		is_need_report = OSAL_TRUE;
	}

	last_cost = curr_cost;
	
}
bool RaPing::parseByJson(const std::string &input)
{
    bool parsingSuccessful = false;
    Json::Reader reader2; 
    try{
        Json::Value root;
        parsingSuccessful = reader2.parse(input,root);
        if(parsingSuccessful){
            Json::Value::Members members(root.getMemberNames() );
            if ( !members.empty() ){
                Json::Value::Members::iterator it = members.begin();
                while(true){
                    const std::string &name = *it;
                    const Json::Value &childValue = root[name];
                    if(childValue.isInt()){
                        int attvalue = childValue.asInt();
                        AttributesEntry entry(name,attvalue);
                        OSAL_trace(eRA, eDebug,"name: %s , attvalue : %d",name.c_str(),attvalue);
                        //pushbackAttributeData(entry);
                    }else if(childValue.isUInt64()){
                        int attvalue = childValue.asUInt64();
                        AttributesEntry entry(name,attvalue);
                        OSAL_trace(eRA, eDebug,"name: %s , attvalue : %d",name.c_str(),attvalue);
                        //pushbackAttributeData(entry);
                    }
                    else if(childValue.isString()){					
                        const std::string attvalue = childValue.asString();				
                        AttributesEntry entry(name,attvalue);
                        OSAL_trace(eRA, eDebug,"name: %s , attvalue : %s",name.c_str(),attvalue.c_str());
                       // pushbackAttributeData(entry);
                    } 
                    else if (childValue.isArray()) { 
                        Json::Value tmp_val = childValue; 
                        Json::FastWriter fw; 
                        std::string attvalue = fw.write(tmp_val); 
                        AttributesEntry entry(name, attvalue); 
                        OSAL_trace(eRA, eDebug,"name: %s , attvalue : %s , size : %d",name.c_str(),attvalue.c_str(),attvalue.size());

                        for(Json::Value::const_iterator it = childValue.begin(); it!=childValue.end(); it++){
							const Json::Value &arr=*it;
							const std::string nbr = arr.asString();
							OSAL_trace(eRA, eDebug, "---- %s ",nbr.c_str());
							AttributesEntry entry("nbr",nbr);
                       }
                    }
                    else if(childValue.isObject()){
                        Json::Value t;
                        OSAL_trace(eRA, eDebug,"obj:%s\n",childValue.toStyledString().c_str());
                        bool p = reader2.parse(childValue.toStyledString(),t);
                        if(p){
                            Json::Value::Members members( t.getMemberNames() );
                            if ( !members.empty() ){
                                Json::Value::Members::iterator it = members.begin();
                                while(true){
                                    const std::string &name = *it;
                                    const Json::Value &childValue = t[name];

                                    if(childValue.isInt()){
                                        int attvalue = childValue.asInt();
                                        AttributesEntry entry(name,attvalue);
                                        OSAL_trace(eRA, eDebug,"name: %s , attvalue : %d",name.c_str(),attvalue);
                                       // pushbackAttributeData(entry);
                                    }else if(childValue.isString()){					
                                        const std::string attvalue = childValue.asString();				
                                        AttributesEntry entry(name,attvalue);
                                        OSAL_trace(eRA, eDebug,"name: %s , attvalue : %s",name.c_str(),attvalue.c_str());
                                       // pushbackAttributeData(entry);
                                    }
                                    else if(childValue.isObject()){
                                        const std::string attvalue = childValue.toStyledString();
                                        AttributesEntry entry(name,attvalue);
                                        OSAL_trace(eRA, eDebug,"name: %s , attvalue : %s",name.c_str(),attvalue.c_str());
                                        //pushbackAttributeData(entry);
                                    }
                                    if ( ++it == members.end() ){
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if ( ++it == members.end() ){
                        break;
                    }
                }
            }

        }else{
            OSAL_trace(eRA, eError,"json parse fail ...");
        }
    } catch(const std::exception &e) {
        OSAL_trace(eRA, eDebug, "Catch Exception: : %s",e.what());
        return false;
    }
    return parsingSuccessful;
}

OSAL_INT32 RaPing::createPingSocket()
{
	struct sockaddr_in selfIpAddr;
	struct protoent *protocol;
	
	if( (protocol=getprotobyname("icmp") )==NULL) { 
		OSAL_trace(eRA, eError, "create_ping_sock: getprotobyname err.");
		return OSAL_ERROR;
	}
	memset(&selfIpAddr, 0, sizeof(struct sockaddr_in));
	selfIpAddr.sin_family = AF_INET;
	selfIpAddr.sin_addr.s_addr = inet_addr(agentAddr.c_str());
	if((sock = socket(AF_INET,SOCK_RAW,protocol->p_proto))<0){ 
		OSAL_trace(eRA, eError, "create_ping_sock: socket SOCK_RAW err");
		return OSAL_ERROR;
	}
	OSAL_INT32 optval=1;
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR ,(void*)&optval, sizeof(optval)) == -1){
		OSAL_trace(eRA, eError,"rtpc_create_sock:setsockopt SO_REUSEADDR err: %s.", strerror(errno));
		close (sock);
		sock = -1;
        return OSAL_ERROR;
	}
	if(bind(sock, (struct sockaddr*)&selfIpAddr, sizeof(selfIpAddr)) < 0) {
		OSAL_trace(eRA, eError, "create_ping_sock: bind ping addr to rtpp err.");
		close (sock);
		sock = -1;
		return OSAL_ERROR;
	}
	OSAL_trace(eRA, eDebug, "create_ping_sock: create ping socket: %d\n",sock);
	
	if (OSAL_OK != OSAL_async_select (eRA, sock, RA_PING_MSG, OSAL_NULL, OSAL_NULL)){
		OSAL_trace (eRA, eError, "create_ping_sock: select raw msgSocket failed.");
		close (sock);
		sock = -1;
		return OSAL_ERROR;
  	}

	return OSAL_OK;
}

OSAL_INT32 RaPing::createBakPingSocket()
{
	struct sockaddr_in selfIpAddr;
	struct protoent *protocol;

	if(sockBak > 0){
		OSAL_trace(eRA,eInfo,"sockBak is inited!");
		return OSAL_OK;
	}
	
	if( (protocol=getprotobyname("icmp") )==NULL) { 
		OSAL_trace(eRA, eError, "create_ping_sock: getprotobyname err.");
		return OSAL_ERROR;
	}
	memset(&selfIpAddr, 0, sizeof(struct sockaddr_in));
	selfIpAddr.sin_family = AF_INET;
	selfIpAddr.sin_addr.s_addr = inet_addr(agentAddrBak.c_str());
	if((sockBak = socket(AF_INET,SOCK_RAW,protocol->p_proto))<0){ 
		OSAL_trace(eRA, eError, "create_ping_sock: socket SOCK_RAW err");
		return OSAL_ERROR;
	}
	OSAL_INT32 optval=1;
	if(setsockopt(sockBak, SOL_SOCKET, SO_REUSEADDR ,(void*)&optval, sizeof(optval)) == -1){
		OSAL_trace(eRA, eError,"rtpc_create_sock:setsockopt SO_REUSEADDR err: %s.", strerror(errno));
		close (sockBak);
		sockBak = -1;
        return OSAL_ERROR;
	}
	if(bind(sockBak, (struct sockaddr*)&selfIpAddr, sizeof(selfIpAddr)) < 0) {
		OSAL_trace(eRA, eError, "create_ping_sock: bind ping addr %s err.",agentAddrBak.c_str());
		close (sockBak);
		sockBak = -1;
		return OSAL_ERROR;
	}
	OSAL_trace(eRA, eDebug, "create_ping_sock: create ping socket: %d\n",sockBak);
	
	if (OSAL_OK != OSAL_async_select (eRA, sockBak, RA_PING_BAK_MSG, OSAL_NULL, OSAL_NULL)){
		OSAL_trace (eRA, eError, "create_ping_sock: select raw msgSocket failed.");
		close (sockBak);
		sockBak = -1;
		return OSAL_ERROR;
  	}

	return OSAL_OK;
}

bool RaPing::parseJsonNbList(const std::string &input)
{
	bool parsingSuccessful = false;
	Json::Reader reader2; 
	Json::Value root;
	parsingSuccessful = reader2.parse(input,root);
	if(parsingSuccessful){
		Json::Value rtppip = root["rtpp"];
		Json::Value nbr = root["nbr"];
		std::string  rtppAddr = rtppip.asString();
		OSAL_trace(eRA, eDebug, "agentAddr : %s , agentAddrBak : %s",agentAddr.c_str(),agentAddrBak.c_str());	
		if(rtppAddr == agentAddr){
			clearNbrHost();
			for(Json::Value::const_iterator it = nbr.begin(); it!=nbr.end(); it++){
				const Json::Value &arr=*it;
				OSAL_trace(eRA, eDebug, "[%s] nbr: %s ",rtppAddr.c_str(),arr.asString().c_str());
				addNbrHost(arr.asString());
            }
		}else if(rtppAddr == agentAddrBak){
			clearNbrHostBak();
			for(Json::Value::const_iterator it = nbr.begin(); it!=nbr.end(); it++){
				const Json::Value &arr=*it;
				OSAL_trace(eRA, eDebug, "[%s] nbr: %s ",rtppAddr.c_str(),arr.asString().c_str());
				addNbrHostBak(arr.asString());
            }
		}else
			OSAL_trace(eRA, eDebug, "rtppAddr %s is not my addr",rtppAddr.c_str());		
	}else
		OSAL_trace(eRA, eError,"json parse fail ...");
	
	return parsingSuccessful;
}
void RaPing::startTxPingTimer()
{
	OSAL_timerMsgHdrT timerMsg;

	timerMsg.moduleId = eRA;
	timerMsg.timerMsgType = eOsalSysMsgIdTimer;
	timerMsg.param1 = TIMER_TX_PING;
	txPingTimer = OSAL_stimerStart(&timerMsg, pingCfg.pingIntv);
}

void RaPing::startCalcPingTimer()
{
	OSAL_timerMsgHdrT timerMsg;

	timerMsg.moduleId = eRA;
	timerMsg.timerMsgType = eOsalSysMsgIdTimer;
	timerMsg.param1 = TIMER_CALC_PING;
	calcPingTimer = OSAL_stimerStart(&timerMsg, pingCfg.calcIntv*1000);
}
void RaPing::addNbrHost(const std::string &addrStr)
{
	HostEntry entry(addrStr);
	nbrHost.insert(HostEntryMap::value_type (entry.getIpAddr(),entry));
}
void RaPing::addNbrHostBak(const std::string &addrStr)
{
	HostEntry entry(addrStr);
	nbrHostBak.insert(HostEntryMap::value_type (entry.getIpAddr(),entry));
}

OSAL_UINT16 RaPing::calcSum(OSAL_UINT16 *buffer, OSAL_UINT32 length)
{
    unsigned long sum;
    for (sum=0; length>1; length-=2) 
		sum += *buffer++;	

    if (length==1)
		sum += (char)*buffer;

    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16);			
    return ~sum;
}

long RaPing::timevalDiff( struct timeval *a, struct timeval *b )
{
    return (a->tv_sec - b->tv_sec)*1000000 + (a->tv_usec - b->tv_usec);
} 
void RaPing::txPingPkt(HostEntry &toHost,OSAL_INT32 fd)
{
	OSAL_CHAR buff[ICMP_PK_LEN + ICMP_MINLEN] = {0};
	size_t pktSize = ICMP_PK_LEN + ICMP_MINLEN;
	struct sockaddr_in addr;

	if(fd < 0){
		OSAL_trace(eRA, eError,"sock to :%s has not inited!",toHost.getHost().c_str());
		return;
	}

	struct icmp *icp = (struct icmp *) buff;
	icp->icmp_type = RA_ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = htons(icmpSeq++%65535);
	icp->icmp_id = htons(ident);
	
	//for (n = ((void*)&icp->icmp_data - (void *)icp); n < pktSize; ++n) {
		//buff[n] = random() & 0xFF;
	//}
	

	icp->icmp_cksum = calcSum((OSAL_UINT16 *) icp, pktSize);
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, toHost.getHost().c_str(), &addr.sin_addr);
	OSAL_INT32 n = sendto(fd, buff, pktSize, 0, (struct sockaddr*)&addr, sizeof(addr));
	if(n > 0){
		//OSAL_trace(eRA, eDebug,"TX ping to %s OK!",toHost.getHost().c_str());
		SEQMAP_VALUE seqEntry;
		gettimeofday( &seqEntry.pingTs,NULL );
		seqEntry.pingCnt = toHost.num_sent;
		seqEntry.hostNbr = addr.sin_addr.s_addr;
		seqMap[ntohs(icp->icmp_seq)] = seqEntry;
		toHost.num_sent++;
		toHost.num_sent_i++;
	}else
		OSAL_trace(eRA, eError,"TX ping to %s fail! ret : %d,errno : %d",toHost.getHost().c_str(),n,errno);
	//OSAL_trace(eRA, eDebug,"sock:%d sendto %s %04x,pktSize:%d, n : %d,errno:%d",sock,host.c_str(),addr.sin_addr,pktSize,n,errno);
	//return n;
}

void RaPing::txPingTimeOut()
{
	if(nbrHost.size() > 0){
		for(auto iter = nbrHost.begin() ; iter != nbrHost.end() ; iter++){
			HostEntry &entry = iter->second;
			txPingPkt(entry,sock);
		}
	}
	
	if(nbrHostBak.size() > 0){
		for(auto iterbak = nbrHostBak.begin() ; iterbak != nbrHostBak.end() ; iterbak++){
			HostEntry &entry = iterbak->second;
			txPingPkt(entry,sockBak);
		}
	}
}

void RaPing::calcTimeOut()
{
	Json::Value root,rootBak;
	Json::Value list,listBak;
	OSAL_BOOL need_report = OSAL_FALSE;
	
	if(nbrHost.size() > 0){
		for(auto iter = nbrHost.begin() ; iter != nbrHost.end() ; iter++){
			HostEntry &entry = iter->second;
			entry.calc_i();
			Json::Value item;

			//only one need report , the ping result is all need report
			if (entry.is_need_report == OSAL_TRUE)
				need_report = OSAL_TRUE;
			/*
			*只上报存活的邻居信息
			*/
			if(entry.getAvgRtt() != RA_NBR_UNREACH){
				item["ip"] = Json::Value(entry.getHost());
				item["delay"] = Json::Value(entry.getAvgRtt());
				item["lost"] = Json::Value(entry.getLossRate());

				list.append(item);
				entry.resetCalc_i();
			}
		}
		if(list.size() > 0 && need_report == OSAL_TRUE){
			root["nbr"] = Json::Value(list);
			root["rtpp"] = Json::Value(agentAddr);

			OSAL_trace(eRA, eDebug,"RA_NB_STAT_REP------>%s",root.toStyledString().c_str());
			if(tx_tcp_msg_json(RA_NB_STAT_REP,root) < 0)
				OSAL_trace(eRA, eError,"TX RA_NB_STAT_REP falied!");
		}
	}

	need_report = OSAL_FALSE;
	
	if(nbrHostBak.size() > 0){
		for(auto iterbak = nbrHostBak.begin() ; iterbak != nbrHostBak.end() ; iterbak++){
			HostEntry &entry = iterbak->second;
			entry.calc_i();
			Json::Value item;

			//only one need report , the ping result is all need report
			if (entry.is_need_report == OSAL_TRUE)
				need_report = OSAL_TRUE;
			
			if(entry.getAvgRtt() != RA_NBR_UNREACH){
				item["ip"] = Json::Value(entry.getHost());
				item["delay"] = Json::Value(entry.getAvgRtt());
				item["lost"] = Json::Value(entry.getLossRate());
				listBak.append(item);
				entry.resetCalc_i();
			}
		}

		if(listBak.size() > 0 && need_report == OSAL_TRUE){
			rootBak["nbr"] = Json::Value(listBak);
			rootBak["rtpp"] = Json::Value(agentAddrBak);

			OSAL_trace(eRA, eDebug,"RA_NB_STAT_REP------>%s",rootBak.toStyledString().c_str());
			if(tx_tcp_msg_json(RA_NB_STAT_REP,rootBak) < 0)
				OSAL_trace(eRA, eError,"TX RA_NB_STAT_REP falied!");
		}
	}
}

void RaPing::showHost()
{
	printf ("main ip NBR\n");
	printf ("%-15s %-10s %-10s %-15s\n", "nbr ip", "last cost", "status", "admin status");
	for(auto iter = nbrHost.begin() ; iter != nbrHost.end() ; iter++){
		HostEntry &entry = iter->second;
		printf("%-15s %-10d %-10s %-15s\n",entry.getHost().c_str(), entry.last_cost, entry.getStatus()?"active":"dead",
			(entry.admin_disconn == OSAL_TRUE) ? "disconn" : "connect");
	}

	printf ("bak ip NBR\n");
	printf ("%-15s %-10s %-10s %-15s\n", "nbr ip", "last cost","status", "admin status");
	for(auto iterbak = nbrHostBak.begin() ; iterbak != nbrHostBak.end() ; iterbak++){
		HostEntry &entry = iterbak->second;
		printf("%-15s %-10d %-10s %-15s\n",entry.getHost().c_str(),entry.last_cost, entry.getStatus()?"active":"dead",
			(entry.admin_disconn == OSAL_TRUE) ? "disconn" : "connect");
	}
}


void RaPing::set_nbr_admin_disconn(OSAL_INT8 *nbr_ip, OSAL_INT32 status)
{
	for(auto iter = nbrHost.begin() ; iter != nbrHost.end() ; iter++){
		HostEntry &entry = iter->second;
		if (!strcmp(entry.getHost().c_str(), nbr_ip))
			entry.admin_disconn = status;
	}

	for(auto iterbak = nbrHostBak.begin() ; iterbak != nbrHostBak.end() ; iterbak++){
		HostEntry &entry = iterbak->second;
		if (!strcmp(entry.getHost().c_str(), nbr_ip))
			entry.admin_disconn = status;
	}
		
}

void RaPing::rxPingPkt(OSAL_INT32 fd)
{
	OSAL_CHAR buffer[4096] = {0};
	OSAL_INT32 len = sizeof(buffer);
	struct sockaddr_in saddr;
	socklen_t saddr_len = sizeof(saddr);
	struct timeval curTime; 

	OSAL_INT32 n = recvfrom( fd, buffer, len, 0, (struct sockaddr *)&saddr, &saddr_len );
	if(n < 0)
		return;
		
	struct ip *ip = ( struct ip* )buffer;
	OSAL_INT32 hlen = ip->ip_hl << 2;
	if(n < sizeof(struct icmp))
		return;
	struct icmp *icp = ( struct icmp* )( buffer + hlen );
	if( icp->icmp_type != RA_ICMP_ECHOREPLY )
		return;
		
	SEQMAP_VALUE seqEntry = seqMap[ntohs(icp->icmp_seq)];
	HostEntryMap::iterator it = nbrHost.find(seqEntry.hostNbr);
	if(it == nbrHost.end()){
		it = nbrHostBak.find(seqEntry.hostNbr);
		if(it == nbrHostBak.end())
			return;
	}
		
	HostEntry &entry = it->second;	
	gettimeofday( &curTime, 0 );
	long thisReply = timevalDiff(&curTime,&seqEntry.pingTs);//微秒us
	//OSAL_trace (eRA, eDebug,"RxPingMsg,host:%s,delay:%ul",entry.getHost().c_str(),thisReply);
	entry.total_time += thisReply;
	entry.total_time_i += thisReply;
	entry.num_recv++;
	entry.num_recv_i++;
	//OSAL_trace (eRA, eDebug,"total_time_i:%ul",entry.total_time_i);
	if( !entry.max_reply   || thisReply > entry.max_reply ) entry.max_reply = thisReply;
    if( !entry.min_reply   || thisReply < entry.min_reply ) entry.min_reply = thisReply;
    if( !entry.max_reply_i || thisReply > entry.max_reply_i ) entry.max_reply_i = thisReply;
    if( !entry.min_reply_i || thisReply < entry.min_reply_i ) entry.min_reply_i = thisReply;
}

OSAL_INT32 Routers::parseConf(std::string &listStr)
{
	std::string rtsStr = listStr;
	while(1){
		OSAL_INT32 pos = rtsStr.find('/');
		if(pos == -1){
			if(rtsStr.size() > 0){
				OSAL_INT32 pos1 = rtsStr.find(':');
				if(pos1 == -1)
					return -1;
				else{
					std::string ipStr = rtsStr.substr(0,pos1);
					std::string portStr = rtsStr.substr(pos1+1,rtsStr.size());
					rtEntry rte;
					rte.ipAddr = ipStr;
					rte.port = atoi(portStr.c_str());
					rte.connCount = 0;
					addRte(rte);
					return 0;
				}
					
			}else
				return 0;
		}else{
			std::string preStr = rtsStr.substr(0,pos);
			OSAL_INT32 pos2 = preStr.find(':');
			if(pos2 == -1)
				return -1;
			else{
				std::string ipStr = preStr.substr(0,pos2);
				std::string portStr = preStr.substr(pos2+1,preStr.size());
				rtEntry rte;
				rte.ipAddr = ipStr;
				rte.port = atoi(portStr.c_str());
				rte.connCount = 0;
				addRte(rte);
			}
			std::string afterStr = rtsStr.substr(pos+1,rtsStr.size());
			if(afterStr.size() > 0){
				rtsStr.assign("");
				rtsStr = afterStr;
			}else
				return 0;
		}
		
	}
}

rtEntry Routers::getToConnRte()
{
	rtEntry rteMin;
	rteMin.connCount = 0xffffffff;
	for(auto itor = rtList.begin();itor != rtList.end();itor++){
		if((*itor).connCount < rteMin.connCount){
			rteMin.ipAddr = (*itor).ipAddr.c_str();
			rteMin.port = (*itor).port;
			rteMin.connCount = (*itor).connCount;
		}
	}
	OSAL_trace (eRA, eDebug,"GET rte ipaddr:%s,port:%d",rteMin.ipAddr.c_str(),rteMin.port);
	return rteMin;
}

void Routers::increRteConnCount(rtEntry &rte)
{
	for(auto itor = rtList.begin();itor != rtList.end();itor++){
		if((*itor).ipAddr == rte.ipAddr)
			(*itor).connCount++;
	}
}
std::string Routers::getRtesStr()
{
	std::string rtesStr;
	OSAL_CHAR portStr[16] = {0};
	for(OSAL_INT32 i = 0 ; i < rtList.size() ; i++){
		rtesStr.append(rtList[i].ipAddr);
		rtesStr.append(":");
		memset(portStr,0x0,16);
		sprintf(portStr,"%d",rtList[i].port);
		rtesStr.append(portStr);
		if(i != rtList.size() - 1)
			rtesStr.append("/");
	}

	return rtesStr;
}
void Routers::delRte(std::string &ipaddr)
{
	for(auto itor = rtList.begin();itor != rtList.end();itor++){
		if((*itor).ipAddr == ipaddr){
			rtList.erase(itor);
			return;
		}
	}
}

void nbrProcMsgNbList(OSAL_CHAR *msg_body,OSAL_UINT32 body_len)
{
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	const std::string jsonStr(msg_body);
	OSAL_trace (eRA, eDebug,"msg_body:%s,len:%d",msg_body,body_len);
	pingHd->parseJsonNbList(jsonStr);
}

void nbrRxPingMsg(OSAL_INT32 sockid)
{
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	if(sockid != pingHd->getSockId() && sockid != pingHd->getSockIdBak()){
		OSAL_trace(eRA, eError, "It isn't my pkt,sockid:%d,,my sock:%d,baksock:%d",sockid,pingHd->getSockId(),pingHd->getSockIdBak());
		return;
	}

	pingHd->rxPingPkt(sockid);
}

void nbrCalcTimeoutHd()
{
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	pingHd->calcTimeOut();
}

OSAL_INT32 init_ra_nbr()
{
	if(pingHd){	
		pingHd->startTxPingTimer();
		pingHd->startCalcPingTimer();
		return OSAL_OK;	
	}
		
	ConfigFile *cfg  = ConfigFile::GetInstance();
	//cfg->dump();//FOR debug
	std::string myAddr = cfg->getvalue<std::string>("agent_addr");
	pingHd = new RaPing(myAddr);
	if(pingHd == NULL){
		OSAL_trace(eRA, eError, "new pingHd failed!");
		return OSAL_ERROR;
	}

	std::string myAddrBak = cfg->getvalue<std::string>("agent_addr_bak");
	if(myAddrBak.length() > 0)
		pingHd->setAgentBakAddr( myAddrBak);

	pingHd->pingCfg.pingIntv = atoi(cfg->getvalue<std::string>("ping_pkt_interval").c_str());
	pingHd->pingCfg.calcIntv = atoi(cfg->getvalue<std::string>("ping_calc_interval").c_str());
	pingHd->pingCfg.cost_thred = atoi(cfg->getvalue<std::string>("nbr_cost_threshold").c_str());
	pingHd->startTxPingTimer();
	pingHd->startCalcPingTimer();

	OSAL_INT32 ret = pingHd->createPingSocket();
	if(ret < 0) {
		OSAL_trace(eRA, eError, "createPingSocket failed!");
		return OSAL_ERROR;
	}

	return OSAL_OK;
}

void nbrTxPingTimeoutHd()
{
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	pingHd->txPingTimeOut();
}

void nbrClearNbrHostMap()
{
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	pingHd->clearNbrHost();
}

void nbrResetTxPingTimer()
{
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	pingHd->stopTxPingTimer();
	pingHd->startTxPingTimer();
}

void nbrResetCalcPingTimer()
{	
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	pingHd->stopCalcPingTimer();
	pingHd->startCalcPingTimer();
}
void nbrStartTxPingTimer()
{
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	pingHd->startTxPingTimer();
}

void nbrStartCalcPingTimer()
{	
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	pingHd->startCalcPingTimer();
}

void nbrStopTxPingTimer()
{
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	pingHd->stopTxPingTimer();
}

void nbrStopCalcPingTimer()
{	
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	pingHd->stopCalcPingTimer();
}

void nbrShowPingConf()
{
	if(pingHd){		
		printf("ping_calc_interval      :    %d\n",pingHd->pingCfg.calcIntv);
		printf("ping_pkt_interval       :    %d\n",pingHd->pingCfg.pingIntv);
		printf("nbr_cost_threshold       :    %d\n",pingHd->pingCfg.cost_thred);
	}else{
		printf("ping_calc_interval      :    5\n");
		printf("ping_pkt_interval       :    500\n");
		printf("nbr_cost_threshold       :   50\n");
	}
}

void nbrShowHost()
{
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}
	pingHd->showHost();
}

void nbrCreateBakSocket()
{
	if(!pingHd){
		OSAL_trace (eRA, eError,"pingHd has not been inited!");
		return;
	}

	pingHd->createBakPingSocket();
}

OSAL_INT32 init_rts()
{
	rtEntry rte;
	ConfigFile *cfg  = ConfigFile::GetInstance();
	//cfg->dump();//FOR debug
	std::string listStr = cfg->getvalue<std::string>("router_list");
	raRts.parseConf(listStr);

	rte = raRts.getToConnRte();
	ra_set_conn_addr(rte.ipAddr.c_str(),rte.port);
	raRts.increRteConnCount(rte);
}

void rt_switch()
{
	rtEntry rte;
	rte = raRts.getToConnRte();
	ra_set_conn_addr(rte.ipAddr.c_str(),rte.port);
	raRts.increRteConnCount(rte);
}

void rt_shell_add_rte(const OSAL_CHAR *rte)
{
	std::string rteStr(rte);
	OSAL_INT32 pos = rteStr.find(':');
	OSAL_trace(eRA, eDebug, "rte : %s",rte);
	if(pos != -1){
		std::string ipStr = rteStr.substr(0,pos);
		std::string portStr = rteStr.substr(pos+1,rteStr.size());	
		rtEntry rte;
		rte.ipAddr = ipStr;
		rte.port = atoi(portStr.c_str());
		rte.connCount = 0;
		raRts.addRte(rte);
	}else{
		printf("%s is wrong format!\n",rte);
		return;
	}

	std::string value = raRts.getRtesStr();
	OSAL_trace(eRA, eDebug, "value : %s",value.c_str());
	refine_cfg_entry(RA_CFG_FILE, RA_ROUTER_LIST, value.c_str());
}

void rt_shell_del_rte(const OSAL_CHAR *rte)
{
	std::string rtStr(rte);
	raRts.delRte(rtStr);
	std::string value = raRts.getRtesStr();
	OSAL_trace(eRA, eDebug, "value : %s",value.c_str());
	refine_cfg_entry(RA_CFG_FILE, RA_ROUTER_LIST, value.c_str());
}


