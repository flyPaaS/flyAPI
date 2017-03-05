//extern void ra_show_conf();
#include "ra.h"
#include "ra_nbr.h"

#define XARGSTRLEN 1024
extern tcp_conn_t  *raTcpConn;
extern RaPing *pingHd;

extern void nbrShowHost();
extern void rt_shell_add_rte(const OSAL_CHAR *rte);
extern void rt_shell_del_rte(const OSAL_CHAR *rte);


static int xsh_ra_show_config(OSAL_SHELL_ARGS)
{
	BEGIN_OSAL_SHELL_MAP ("Show Router Agent config")
	OSAL_SHELL_NO_ARG()
	END_OSAL_SHELL_MAP ();
	ra_show_conf();
	return OSAL_OK;

}

static int xsh_ra_show_nbr(OSAL_SHELL_ARGS)
{
	BEGIN_OSAL_SHELL_MAP ("Show Router Agent config")
	OSAL_SHELL_NO_ARG()
	END_OSAL_SHELL_MAP ();
	nbrShowHost();
	return OSAL_OK;

}

static OSAL_INT32 xsh_add_router(OSAL_SHELL_ARGS)
{
	OSAL_CHAR raAddr[XARGSTRLEN] = {0};
	OSAL_INT32 ret;
	OSAL_msgHdr msg = {0};
	
	BEGIN_OSAL_SHELL_MAP ("Add a new Router.")
	OSAL_SHELL_STRING_ARG("addr", raAddr, NULL, "New Router Addr:x.x.x.x:y,192.168.0.10:9955")
 	END_OSAL_SHELL_MAP ();
	//printf("-----raAddr:%s\n",raAddr);
	rt_shell_add_rte(raAddr);
	return OSAL_OK;
}

static OSAL_INT32 xsh_del_router(OSAL_SHELL_ARGS)
{
	OSAL_CHAR raAddr[XARGSTRLEN] = {0};
	OSAL_INT32 ret;
	OSAL_msgHdr msg = {0};
	
	BEGIN_OSAL_SHELL_MAP ("Del a existed Router.")
	OSAL_SHELL_STRING_ARG("addr", raAddr, NULL, "Router ipAddr:x.x.x.x")
 	END_OSAL_SHELL_MAP ();

 	if(INADDR_NONE == inet_addr(raAddr)){
		printf("%s is wrong ipv1 addr\n",raAddr);
		return -1;
	}

	rt_shell_del_rte(raAddr);
	return OSAL_OK;
}


static OSAL_INT32 xsh_set_agent_addr(OSAL_SHELL_ARGS)
{
	OSAL_CHAR agentAddr[XARGSTRLEN] = {0};
	OSAL_INT32 ret;
	OSAL_msgHdr msg = {0};
	
	BEGIN_OSAL_SHELL_MAP ("Modify Agent Addr.")
	OSAL_SHELL_STRING_ARG("IPv4 addr", agentAddr, NULL, "New Agent Addr")
 	END_OSAL_SHELL_MAP ()

	if(INADDR_NONE == inet_addr(agentAddr)){
		printf("%s is wrong ipv1 addr\n",agentAddr);
		return -1;
	}
	
	refine_cfg_entry(RA_CFG_FILE, RA_AGENT_ADDR, agentAddr);

	//msg.msgId = RA_RECONFIG;
	//msg.msgSubId = RECFG_AGENT_ADDR;
	memset(raTcpConn->self_ip_str,0x0,sizeof(raTcpConn->self_ip_str));
	strcpy(raTcpConn->self_ip_str,agentAddr);
	//OSAL_sendMsg(eRA,&msg);
	
	return OSAL_OK;
}

static OSAL_INT32 xsh_set_agent_addr_bak(OSAL_SHELL_ARGS)
{
	OSAL_CHAR agentAddr[XARGSTRLEN] = {0};
	OSAL_INT32 ret;
	//OSAL_msgHdr msg = {0};
	
	BEGIN_OSAL_SHELL_MAP ("Modify Agent Bak Addr.")
	OSAL_SHELL_STRING_ARG("IPv4 addr", agentAddr, NULL, "New Agent Bak Addr")
 	END_OSAL_SHELL_MAP ()

	if(INADDR_NONE == inet_addr(agentAddr)){
		printf("%s is wrong ipv1 addr\n",agentAddr);
		return -1;
	}
	
	refine_cfg_entry(RA_CFG_FILE, RA_AGENT_ADDR_BAK, agentAddr);

	//msg.msgId = RA_RECONFIG;
	//msg.msgSubId = RECFG_AGENT_ADDR;
	memset(raTcpConn->bak_ip_str,0x0,sizeof(raTcpConn->bak_ip_str));
	strcpy(raTcpConn->bak_ip_str,agentAddr);
	raTcpConn->bakFlag = 1;
	//OSAL_sendMsg(eRA,&msg);
	
	return OSAL_OK;
}


static OSAL_INT32 xsh_set_pkt_intv(OSAL_SHELL_ARGS)
{
	OSAL_CHAR intv[XARGSTRLEN] = {0};
	OSAL_INT32 ret;
	OSAL_msgHdr msg = {0};
	
	BEGIN_OSAL_SHELL_MAP ("Modify ping pkt interval.(ms)")
	OSAL_SHELL_STRING_ARG("interval", intv, NULL, "ping pkt interval(100~10000)")
 	END_OSAL_SHELL_MAP ()

	if(atoi(intv) > 10000 || atoi(intv) < 100){
		printf("%s is wrong interval value\n",intv);
		return -1;
	}
	
	refine_cfg_entry(RA_CFG_FILE, RA_PING_PKT_INTV, intv);

	msg.msgId = RA_RECONFIG;
	msg.msgSubId = RECFG_PKT_INTV;
	if(pingHd){
		pingHd->pingCfg.pingIntv = atoi(intv);
		OSAL_sendMsg(eRA,&msg);
	}
	
	return OSAL_OK;
}

static OSAL_INT32 xsh_set_calc_intv(OSAL_SHELL_ARGS)
{
	OSAL_CHAR intv[XARGSTRLEN] = {0};
	OSAL_INT32 ret;
	OSAL_msgHdr msg = {0};
	
	BEGIN_OSAL_SHELL_MAP ("Modify ping calc interval.(s)")
	OSAL_SHELL_STRING_ARG("interval", intv, NULL, "ping calc interval(3~300)")
 	END_OSAL_SHELL_MAP ()

	if(atoi(intv) > 300 || atoi(intv) < 3){
		printf("%s is wrong interval value\n",intv);
		return -1;
	}
	
	refine_cfg_entry(RA_CFG_FILE, RA_PING_CALC_INTV, intv);

	msg.msgId = RA_RECONFIG;
	msg.msgSubId = RECFG_CALC_INTV;
	if(pingHd){
		pingHd->pingCfg.calcIntv = atoi(intv);
		OSAL_sendMsg(eRA,&msg);
	}
	
	return OSAL_OK;
}

static OSAL_INT32 xsh_set_cost_threshold(OSAL_SHELL_ARGS)
{
	OSAL_INT8  thred[8];
	
	BEGIN_OSAL_SHELL_MAP ("Modify ping calc interval.(s)")
	OSAL_SHELL_STRING_ARG("threshold", thred, NULL, "cost of threshold")
 	END_OSAL_SHELL_MAP ()

	
	refine_cfg_entry(RA_CFG_FILE, RA_COST_THRESHOLD, thred);

	if(pingHd){
		pingHd->pingCfg.cost_thred = atoi(thred);
	}
	
	return OSAL_OK;
}

static OSAL_INT32 xsh_set_nbr_disconn(OSAL_SHELL_ARGS)
{
	OSAL_INT32 status;
	OSAL_INT8  rtpp[16];
	
	BEGIN_OSAL_SHELL_MAP ("Modify ping calc interval.(s)")
	OSAL_SHELL_INT_ARG("status", &status, NULL, "admin status of rtpp connection, 1: set to disconnect 0:clear to disconnect")
	OSAL_SHELL_STRING_ARG("rtpp", rtpp, NULL, "ip of disconnected RTPP")
 	END_OSAL_SHELL_MAP ()

	if(pingHd){	
		pingHd->set_nbr_admin_disconn(rtpp, status);
	}
	
	return OSAL_OK;
}

void ra_init_shell ()
{	
	OsalSNode parent;
	parent = osal_register_snode (NULL, (char*)"RA", NULL, 0);
	
	osal_register_snode (parent, "ShowConfig", xsh_ra_show_config, 0);
	osal_register_snode (parent, "AddRouter", xsh_add_router, 0);
	osal_register_snode (parent, "DelRouter", xsh_del_router, 0);
	osal_register_snode (parent, "SetAgentAddr", xsh_set_agent_addr, 0);
	osal_register_snode (parent, "SetAgentBakAddr", xsh_set_agent_addr_bak, 0);
	osal_register_snode (parent, "SetPingPktIntv", xsh_set_pkt_intv, 0);
	osal_register_snode (parent, "SetPingCalcIntv", xsh_set_calc_intv, 0);
	osal_register_snode (parent, "ShowNbr", xsh_ra_show_nbr, 0);
	osal_register_snode (parent, "SetCostThrd", xsh_set_cost_threshold , 0);
	osal_register_snode (parent, "SetNbrDisconn", xsh_set_nbr_disconn , 0);
}


