#include "rtpp_session.h"
#include "rtpp_util.h"
#include "rtpp_mixer.h"

rtpp_ss_pool_t rtpp_ss_pool;
rtpp_hash_table rtpp_hash_tbl;


OSAL_INT32 rtpp_session_init(void)
{
	rtpp_session_t *s;
	OSAL_INT32 i = 0, j = 0;
	
	s = (rtpp_session_t*)osal_allocate(sizeof(rtpp_session_t)*RTPP_SESSION_MAX_NUM,DEFAULT_FLAGS | MEMF_ZERO_MEMORY, mem_default, MAGIC_NUMBER('r','t','p','p'), NULL);
	if(!s){
		OSAL_trace(eRTPP, eError,"alloc session pool failed");
		return -1;
	}
	for(i = 0;i < RTPP_SESSION_MAX_NUM;i++){
		s[i].id = i;
		s[i].next_id = i+1;
		for(j = 0; j < PORT_NUM_MAX; j++) {
			s[i].left.audio[j].trans= &s[i].right.audio[j];
			s[i].right.audio[j].trans= &s[i].left.audio[j];
			s[i].left.video[j].trans= &s[i].right.video[j];
			s[i].right.video[j].trans= &s[i].left.video[j];

			s[i].left.audio[j].ss= &s[i];
			s[i].right.audio[j].ss= &s[i];
			s[i].left.video[j].ss= &s[i];
			s[i].right.video[j].ss= &s[i];
		}
		pthread_mutex_init(&s[i].splock, NULL);		
	}
	
	s[i-1].next_id = RTPP_NULL_ID;

	rtpp_ss_pool.malloc = s;
	rtpp_ss_pool.free_sid = 0;
	rtpp_ss_pool.free_eid = RTPP_SESSION_MAX_NUM-1;
	pthread_mutex_init(&rtpp_ss_pool.lock, NULL);

	for(i = 0;i < RTPP_HASH_MAX_LENTH;i++){
		pthread_mutex_init(&rtpp_hash_tbl.enter[i].lock, NULL);
	}

	OSAL_trace(eRTPP, eDebug,"session all init ok");
	return 0;
}
OSAL_INT32 rtpp_session_uninit(void)
{
	OSAL_INT32 i = 0;
	
	pthread_mutex_destroy(&rtpp_ss_pool.lock);
	osal_free(rtpp_ss_pool.malloc);
	for(i = 0;i < RTPP_HASH_MAX_LENTH;i++){
		pthread_mutex_destroy(&rtpp_hash_tbl.enter[i].lock);
	}
	return 0;
}

OSAL_UINT32 rtpp_hashvalue(const OSAL_CHAR *str)
{
	int i, l = (strlen(str)+1) / 2;
	unsigned int ret = 0;
	unsigned short *s = (unsigned short*)str;
	
	for (i = 0; i < l; i++){
		ret ^= (s[i] << (i & 0x0F));
	}
	return ret%RTPP_HASH_MAX_LENTH;
}


OSAL_INT32 rtpp_add2hash(rtpp_session_t *ss)
{
	OSAL_INT32 i = 0;
	
	i = rtpp_hashvalue(ss->call_id);
	
	pthread_mutex_lock(&rtpp_hash_tbl.enter[i].lock);
	ss->next = rtpp_hash_tbl.enter[i].first;
	ss->pre = 0;
	rtpp_hash_tbl.enter[i].first = ss;
	if(ss->next){
		ss->next->pre = ss;
	}
	pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
	atomic_inc(&rtpp_hash_tbl.used);
	return 0;
}

OSAL_INT32 rtpp_remove_hash(rtpp_session_t *ss)
{
	OSAL_INT32 i = 0;
	
	i = rtpp_hashvalue(ss->call_id);
	
	pthread_mutex_lock(&rtpp_hash_tbl.enter[i].lock);
	if(ss->pre){
		ss->pre->next = ss->next;
	}else{
		rtpp_hash_tbl.enter[i].first = ss->next;
	}
	if(ss->next){
		ss->next->pre = ss->pre;
	}
	pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
	atomic_dec(&rtpp_hash_tbl.used);
	return 0;
}

rtpp_session_t* rtpp_new_session(OSAL_CHAR *callid)
{
	OSAL_INT32 f;
	rtpp_session_t *ss;

	pthread_mutex_lock(&rtpp_ss_pool.lock);
	f = rtpp_ss_pool.free_sid;
	if(RTPP_NULL_ID == f){
		pthread_mutex_unlock(&rtpp_ss_pool.lock);
		return (rtpp_session_t*)0;
	}
	rtpp_ss_pool.free_sid = rtpp_ss_pool.malloc[f].next_id;
	if(RTPP_NULL_ID == rtpp_ss_pool.free_sid){
		rtpp_ss_pool.free_eid = RTPP_NULL_ID;
	}
	pthread_mutex_unlock(&rtpp_ss_pool.lock);

	ss = &rtpp_ss_pool.malloc[f];
	ss->inuse = 1;
	strcpy(ss->call_id,callid);
	
	OSAL_trace(eRTPP, eDebug,"alloc session id %d",f);

	rtpp_add2hash(ss);
	
	return ss;
}

/*RET 0*/
OSAL_INT32 rtpp_find_session(OSAL_CHAR *callid ,rtpp_session_t **ss)
{
	OSAL_INT32 i = 0;
	rtpp_session_t *tmp;

	i = rtpp_hashvalue(callid);
	pthread_mutex_lock(&rtpp_hash_tbl.enter[i].lock);
	tmp = rtpp_hash_tbl.enter[i].first;
	while(tmp){
		if(!strcmp(tmp->call_id,callid)){
			if(ss) *ss = tmp;
			pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
			return 0;		
		}

		tmp = tmp->next;
	}
	pthread_mutex_unlock(&rtpp_hash_tbl.enter[i].lock);
	return -1;
}

OSAL_INT32 rtpp_free_session(rtpp_session_t *ss)
{
	OSAL_INT32 id = 0;
	OSAL_INT32 f;
	OSAL_INT32 i;
	
	if(!ss->inuse){
		OSAL_trace(eRTPP, eError,"ss possible free twice!");
		return 0;
	}

	rtpp_remove_hash(ss);

	rtpp_media_end(ss);

	//del conference
	if(ss->inst){
		if(Mixer_delete_conference(ss->inst) < 0){
			OSAL_trace(eRTPP, eError, "fail to remove mixer conference");
 		}
	}

	//del fec
	if(ss->fec_inst){
		OSAL_trace(eRTPP, eInfo, "fec_inst is %p", ss->fec_inst);
		if(fec_destroy(ss->fec_inst) < 0){
			OSAL_trace(eRTPP, eError, "fail to remove directcall fec");
 		}
		ss->fec_inst = NULL;
	}

	for(i = 0; i < PORT_NUM_MAX; i++) {
		rtpp_rc_end(ss->left.audio[i].rcctr);
		rtpp_rc_end(ss->right.audio[i].rcctr);
		rtpp_jt_end(&ss->left.audio[i],ss);
		rtpp_jt_end(&ss->right.audio[i],ss);
		rtpp_ssrc_end(&ss->left.audio[i]);
		rtpp_ssrc_end(&ss->right.audio[i]);
		
		if (ss->left.audio[i].rrcs != OSAL_NULL) rclose(ss->left.audio[i].rrcs);
		if (ss->right.audio[i].rrcs != OSAL_NULL) rclose(ss->right.audio[i].rrcs);

		if(ss->left.audio[i].p) rtpp_disselct_free_port(ss->mod_id,ss->left.audio[i].p);
		if(ss->left.video[i].p) rtpp_disselct_free_port(ss->mod_id,ss->left.video[i].p);
		if(ss->right.audio[i].p) rtpp_disselct_free_port(ss->mod_id,ss->right.audio[i].p);
		if(ss->right.video[i].p) rtpp_disselct_free_port(ss->mod_id,ss->right.video[i].p);

		if(ss->right.audio[i].pbak) rtpp_disselct_free_port(ss->mod_id,ss->right.audio[i].pbak);
		if(ss->right.video[i].pbak) rtpp_disselct_free_port(ss->mod_id,ss->right.video[i].pbak);	
	}

	if(ss->mtime)  OSAL_stimerStop(ss->mtime);
		
	id = ss->id;
	memset(ss,0x00,sizeof(rtpp_session_t));
	ss->id = id;
	ss->next_id = RTPP_NULL_ID;
	for (i = 0; i < PORT_NUM_MAX; i++) {
		ss->left.audio[i].trans = &ss->right.audio[i];
		ss->right.audio[i].trans = &ss->left.audio[i];
		ss->left.video[i].trans = &ss->right.video[i];
		ss->right.video[i].trans = &ss->left.video[i];

		ss->left.audio[i].ss = ss;
		ss->right.audio[i].ss = ss;
		ss->left.video[i].ss = ss;
		ss->right.video[i].ss = ss;
	}
	
	OSAL_trace(eRTPP, eDebug,"free session id %d",id);

	pthread_mutex_lock(&rtpp_ss_pool.lock);
	f = rtpp_ss_pool.free_eid;
	if(RTPP_NULL_ID == f){
		rtpp_ss_pool.free_sid = ss->id;
	}else{
		rtpp_ss_pool.malloc[f].next_id = ss->id;
	}
	rtpp_ss_pool.free_eid = ss->id;
	pthread_mutex_unlock(&rtpp_ss_pool.lock);
	return 0;
}

OSAL_INT32 rtpp_free_old_session(rtpp_session_t *ss)
{
	OSAL_INT32 id = 0;
	OSAL_INT32 f;
	OSAL_INT32 i;
	
	if(!ss->inuse){
		OSAL_trace(eRTPP, eError,"ss possible free twice!");
		return 0;
	}

	rtpp_remove_hash(ss);

	//del conference
	if(ss->inst){
		if(Mixer_delete_conference(ss->inst) < 0){
			OSAL_trace(eRTPP, eError, "fail to remove mixer conference");
 		}
	}

	//del fec
	if(ss->fec_inst){
		OSAL_trace(eRTPP, eInfo, "fec_inst is %p", ss->fec_inst);
		if(fec_destroy(ss->fec_inst) < 0){
			OSAL_trace(eRTPP, eError, "fail to remove directcall fec");
 		}
	}
	for (i = 0; i < PORT_NUM_MAX; i++) {
		if (ss->left.audio[i].rrcs != OSAL_NULL) rclose(ss->left.audio[i].rrcs);
		if (ss->right.audio[i].rrcs != OSAL_NULL) rclose(ss->right.audio[i].rrcs);
	}

	if(ss->mtime)  OSAL_stimerStop(ss->mtime);
		
	id = ss->id;
	memset(ss,0x00,sizeof(rtpp_session_t));
	ss->id = id;
	ss->next_id = RTPP_NULL_ID;

	for (i = 0; i < PORT_NUM_MAX; i++) {
		ss->left.audio[i].trans = &ss->right.audio[i];
		ss->right.audio[i].trans = &ss->left.audio[i];
		ss->left.video[i].trans = &ss->right.video[i];
		ss->right.video[i].trans = &ss->left.video[i];

	}
	
	
	OSAL_trace(eRTPP, eDebug,"free old session id %d",id);

	pthread_mutex_lock(&rtpp_ss_pool.lock);
	f = rtpp_ss_pool.free_eid;
	if(RTPP_NULL_ID == f){
		rtpp_ss_pool.free_sid = ss->id;
	}else{
		rtpp_ss_pool.malloc[f].next_id = ss->id;
	}
	rtpp_ss_pool.free_eid = ss->id;
	pthread_mutex_unlock(&rtpp_ss_pool.lock);
	return 0;
}

/*改成原子后编译不过，互转有问题*/
OSAL_INT32 rtpp_get_call_count()
{
	//return rtpp_hash_tbl.used;
	return 0;
}



