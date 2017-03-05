/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2007 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_record.h"
#include "rtpp_util.h"
#include "common.h"

#include "OSAL_trace.h"
#include "OSAL_memory.h"
#include "rtpp_main.h"

extern void rtpp_get_record_dir(OSAL_CHAR *buf);

void *ropen(char *dir, rtpp_session_t *sp, char *rname, int side)
{
    rtpp_record_channel_t *rrc;
	file_hdr_record_t  file_hdr_record = {0};
    int rval;

    rrc = (rtpp_record_channel_t*) osal_allocate(sizeof(rtpp_record_channel_t), MEMF_ZERO_MEMORY, mem_default, MAGIC_NUMBER('R','r','r','c'), NULL);
    if (rrc == OSAL_NULL) {
	OSAL_trace(eRTPP, eError,
	"can't allocate memory");
	return OSAL_NULL;
    }
    memset(rrc, 0, sizeof(*rrc));
	sprintf(rrc->rpath, "%s%s_%c", dir, rname, (side != 0) ? 'a' : 'b');

    rrc->fd = open(rrc->rpath, O_WRONLY | O_CREAT | O_TRUNC, DEFFILEMODE);
	
    if (rrc->fd == -1) 
	{
		OSAL_trace(eRTPP, eError,"can't open file %s for writing", rrc->rpath);
		osal_free(rrc);
		return OSAL_NULL;
    }	

    file_hdr_record.codec_pt = SIP_G729;
    //file_hdr_record.codec_pt = sp->pt_rtp[orig];
	OSAL_trace(eRTPP, eInfo,"codec_pt is %d", file_hdr_record.codec_pt);

	rval = write(rrc->fd, &file_hdr_record, sizeof(file_hdr_record_t));
	if (rval == -1) {
	    close(rrc->fd);
		OSAL_trace(eRTPP, eError, "%s: error writing header", rrc->rpath);
	    osal_free(rrc);
	    return OSAL_NULL;
	}
	if (rval < sizeof(file_hdr_record_t)) {
	    close(rrc->fd);
	    OSAL_trace(eRTPP, eError, "%s: short write writing header", rrc->rpath);
	    osal_free(rrc);
	    return OSAL_NULL;
	}

    OSAL_trace (eRTPP, eInfo, "record file %s has been opened", rrc->rpath);

    return (void *)(rrc);
}

static int
flush_rbuf(rtpp_record_channel_t *rrc)
{
    int rval;

    rval = write(rrc->fd, rrc->rbuf, rrc->rbuf_len);
    if (rval != -1) {
	rrc->rbuf_len = 0;
	return 0;
    }

    //rtpp_log_ewrite(RTPP_LOG_ERR, 
     OSAL_trace(eRTPP, eError,
		"error while recording session (%s)", "RTP");
    /* Prevent futher writing if error happens */
    close(rrc->fd);
    rrc->fd = -1;
    return -1;
}

static int prepare_pkt_hdr(char *buf, unsigned short len, pkt_hdr_record_t *head)
{

    memset(head, 0, sizeof(pkt_hdr_record_t));

    head->plen = htons(len);
    return 0;
}

void rwrite(rtpp_record_channel_t *rrc, char *buf, unsigned short len)
{
    struct iovec v[2];
    int rval;
    int hdr_size = sizeof(pkt_hdr_record_t);
    pkt_hdr_record_t head;

    if (rrc->fd == -1)
	    return;

    /* Check if the write buffer has necessary space, and flush if not */
    if ((rrc->rbuf_len + hdr_size + len > sizeof(rrc->rbuf)) && rrc->rbuf_len > 0)
    {
	    if (flush_rbuf(rrc) != 0)
	        return;
    }
    /* Check if received packet doesn't fit into the buffer, do synchronous write  if so */
    if (rrc->rbuf_len + hdr_size + len > sizeof(rrc->rbuf)) 
    {
    	if (prepare_pkt_hdr(buf, len, &head) != 0)
    	    return;

    	v[0].iov_base = (void *)&head;
    	v[0].iov_len = hdr_size;
    	v[1].iov_base = buf;
    	v[1].iov_len = len;

    	rval = writev(rrc->fd, v, 2);
    	if (rval != -1)
    	    return;

    	OSAL_trace(eRTPP, eError, "error while recording session");
    	/* Prevent futher writing if error happens */
    	close(rrc->fd);
    	rrc->fd = -1;
    	return;
    }
    if (prepare_pkt_hdr(buf, len, (pkt_hdr_record_t *)(rrc->rbuf + rrc->rbuf_len)) != 0)
	    return;
    rrc->rbuf_len += hdr_size;
    memcpy(rrc->rbuf + rrc->rbuf_len, buf, len);
    rrc->rbuf_len += len;
}

void rclose(rtpp_record_channel_t *rrc)
{
	char recordFileName[MAX_PATH_LEN + 1];

    if (rrc == NULL)
        return ;

    if (rrc->rbuf_len > 0)
        flush_rbuf(rrc);

    if (rrc->fd != -1)
	    close(rrc->fd);

    rrc->fd = -1;

	sprintf(recordFileName, "%s.rtp" ,rrc->rpath);

    rename(rrc->rpath, recordFileName);

	strcpy(rrc->rpath, recordFileName);
    OSAL_trace (eRTPP, eInfo, "record file %s has been close", rrc->rpath);

    osal_free(rrc);
}

void rtpp_handle_record(OSAL_CHAR *record_dir, OSAL_INT32 side, OSAL_CHAR *record_name, rtpp_session_t *sp)
{
	if(!sp || !record_dir || !record_name)
		return;
	
	if(side){
	    if (sp->left.audio[0].rrcs == OSAL_NULL && record_dir != OSAL_NULL) {
			sp->left.audio[0].rrcs = ropen(record_dir, sp, record_name, side);
			OSAL_trace(eRTPP, eInfo,"starting recording RTP session on left port to %s", record_dir);
	    }		
	}
	else
	{
	    if (sp->right.audio[0].rrcs == OSAL_NULL && record_dir != OSAL_NULL) {
			sp->right.audio[0].rrcs = ropen(record_dir, sp, record_name, side);
			OSAL_trace(eRTPP, eInfo,"starting recording RTP session on right port to %s", record_dir);
	    }
	}
}


//fix me for mutil port on a branche...
void rtpp_check_record(OSAL_CHAR *record_dir, OSAL_INT32 record_flag, OSAL_CHAR *record_name, rtpp_session_t *ss)
{
	if(!ss || !record_dir || !record_name)
		return;
	
	if(record_flag == 0){
		if(ss->left.audio[0].rrcs != OSAL_NULL){
			rclose(ss->left.audio[0].rrcs);
			OSAL_trace(eRTPP, eDebug,"record rpath: %s",ss->left.audio[0].rrcs->rpath);
			remove(ss->left.audio[0].rrcs->rpath);
			ss->left.audio[0].rrcs = OSAL_NULL;
		}
		if(ss->right.audio[0].rrcs != OSAL_NULL){
			rclose(ss->right.audio[0].rrcs);
			remove(ss->right.audio[0].rrcs->rpath);
			ss->right.audio[0].rrcs = OSAL_NULL;
		}			
	}else{
		if(ss->left.audio[0].rrcs == OSAL_NULL){
			OSAL_trace(eRTPP, eInfo,"record call[%s->%s] on left port",ss->f_tag,ss->to_tag);
			rtpp_handle_record(record_dir, 1, record_name, ss);
		}
		if(ss->right.audio[0].rrcs == OSAL_NULL){
			OSAL_trace(eRTPP, eInfo,"record call[%s->%s] on right port",ss->f_tag,ss->to_tag);
			rtpp_handle_record(record_dir, 0, record_name, ss);
		}

	}

}

void rtpp_rc_init(port_info_t *refer)
{
	struct rc_ctr *rcctr = OSAL_NULL;
	DIR *pdir = OSAL_NULL;
	OSAL_CHAR dir[64] = {0},cmd[256] = {0};

	if(0 == rtpp_get_rc_flag()){
		return;
	}
	
	if(!(refer->ss->fec_flag && !refer->fec_mode)){
		OSAL_trace(eRTPP, eDebug, "fec_flag[%d],fec_mode[%d]",refer->ss->fec_flag,refer->fec_mode);
		return;
	}

	refer->fec_rec = 1;
	
	Correlator corr = MAGIC_NUMBER('R','P','r','c');
	rcctr = (struct rc_ctr *)osal_quick_allocate (sizeof (struct rc_ctr), DEFAULT_FLAGS, corr, NULL);
	if(OSAL_NULL == rcctr)
		return ;
		
	memset(rcctr, 0, sizeof(struct rc_ctr));
	rcctr->pre.fd = -1;
	rcctr->after.fd = -1;
	rcctr->pre.chan_type= chan_pre;
	rcctr->after.chan_type= chan_after;
	rcctr->pre.start_seq = rcctr->pre.end_seq = refer->packet.seq;
	rcctr->after.start_seq = rcctr->after.end_seq = refer->packet.seq;
	
	rtpp_get_record_dir(dir);
	if(strlen(dir) == 0)		
		sprintf(dir,"%s","/tmp/lossrecord/");
	else
		sprintf(dir,"%s%s",dir,"lossrecord/");

	if((pdir=opendir(dir)) == OSAL_NULL){
		sprintf(cmd, "mkdir -p %s", dir);
		system(cmd);
	}else
		closedir(pdir);
	  	
	refer->rcctr = 	rcctr;
	strcpy(refer->rcctr->rpath,dir);
	refer->rcctr->init_flag = 1;	
}

static void rtpp_rc_first(port_info_t *refer)
{
	OSAL_CHAR rc_filename[512] = {0},date_str[64] = {0};
	struct tm *curr_tm;
	struct timeval now;
	OSAL_INT32 rval;
	file_hdr_record_t  file_hdr_record = {0};

	if(refer->rcctr->pre.fd > 0)
		return;
	
	gettimeofday(&now,OSAL_NULL);
	curr_tm = localtime( ( time_t* )&now.tv_sec );
	sprintf( date_str, "%04d%02d%02d-%2.2d.%2.2d.%2.2d", (1900+curr_tm->tm_year), (1+curr_tm->tm_mon), curr_tm->tm_mday, \
		curr_tm->tm_hour,curr_tm->tm_min, curr_tm->tm_sec );

	sprintf(rc_filename,"%s%s_%s_%d_%x_pre.rtp",refer->rcctr->rpath,date_str,
		RtppGlobals.localip[refer->p->index],refer->p->port,refer->packet.ssrc);

    refer->rcctr->pre.fd = open(rc_filename, O_WRONLY|O_CREAT);
    if (refer->rcctr->pre.fd == -1) {
		OSAL_trace(eRTPP, eError,"can't open file %s for writing", rc_filename);
		return ;
    }	

    file_hdr_record.codec_pt = SIP_G729;
	rval = write( refer->rcctr->pre.fd,&file_hdr_record , sizeof(file_hdr_record_t));
	if (rval == -1) {
	    close(refer->rcctr->pre.fd);
	    refer->rcctr->pre.fd = -1;
		OSAL_trace(eRTPP, eError, "%s: error writing header", rc_filename);
	    return ;
	}
	
	memset(rc_filename,0x0,512);
	sprintf(rc_filename,"%s%s_%s_%d_%x_after.rtp",refer->rcctr->rpath,date_str,
		RtppGlobals.localip[refer->p->index],refer->p->port,refer->packet.ssrc);
    refer->rcctr->after.fd = open(rc_filename, O_WRONLY|O_CREAT);
    if (refer->rcctr->after.fd == -1) {
    	close(refer->rcctr->pre.fd);
	    refer->rcctr->pre.fd = -1;
		OSAL_trace(eRTPP, eError,"can't open file %s for writing", rc_filename);
		return ;
    }	

	rval = write(refer->rcctr->after.fd,&file_hdr_record , sizeof(file_hdr_record_t));
	if (rval == -1) {
		close(refer->rcctr->pre.fd);
	    refer->rcctr->pre.fd = -1;
	    close(refer->rcctr->after.fd);
	    refer->rcctr->after.fd = -1;
		OSAL_trace(eRTPP, eError, "%s: error writing header", rc_filename);
	    return ;
	}

}
static void  rc_wr_data(struct rc_pktnode *ptr,struct rc_ch *ch,OSAL_INT32 index)
{
	OSAL_INT32 ret;
	
	ret = write(ch->fd,ptr->buf,ptr->len);
	OSAL_trace(eRTPP, eDebug, "write:fd:%d,len:%d,ret:%d,err:%d", ch->fd,ptr->len,ret,errno);
}

static void rtpp_rc_rw_ch(struct rc_ch *ch)
{
	struct rc_pktnode *ptr = NULL;
	OSAL_INT32 i;
	
	if(!ch)
		return;

	OSAL_trace(eRTPP, eDebug, "fd:%d start:%d,end:%d", ch->fd,ch->start_p,ch->end_p);

	if(ch->start_p <= ch->end_p){
		for(i = ch->start_p ; i <= ch->end_p ; i++){
			ptr = (struct rc_pktnode *)ch->rcn[i].data;
			if(ptr && ch->rcn[i].used_flag == 1){
				rc_wr_data(ptr, ch, i);
			}
		}
	}else{
		for(i = ch->start_p ; i < RC_SLOT_NUM ; i++){
			ptr = (struct rc_pktnode *)ch->rcn[i].data;
			if(ptr && ch->rcn[i].used_flag == 1){
				rc_wr_data(ptr, ch, i);
			}
		}
		
		for(i = 0 ; i <= ch->end_p ; i++){
			ptr = (struct rc_pktnode *)ch->rcn[i].data;
			if(ptr && ch->rcn[i].used_flag == 1){
				rc_wr_data(ptr, ch, i);
			}
		}
	}
}

void rtpp_rc_push(port_info_t *refer,struct rc_ch *rch,OSAL_UINT8 *buf, OSAL_INT32 len,OSAL_UINT16 seq)
{
	struct rc_pktnode *node = NULL;
	OSAL_UINT32 hrd_size,buf_size;
	pkt_hdr_record_t *pkt_hrd = NULL;
	OSAL_UINT32 index;
	OSAL_CHAR *pbuf = NULL;
	
	hrd_size = sizeof(pkt_hdr_record_t);
	buf_size = len + hrd_size + sizeof(struct rc_pktnode);
	
	Correlator corr = MAGIC_NUMBER('R','P','r','c');
	pbuf = (OSAL_CHAR *)osal_quick_allocate (buf_size, DEFAULT_FLAGS, corr, NULL);
	if(NULL == pbuf)
		return;
	memset(pbuf,0x00,buf_size);	
	node = (struct rc_pktnode *)pbuf;
	node->len = len + hrd_size;
	pkt_hrd = (pkt_hdr_record_t *)node->buf;
	pkt_hrd->plen =  htons(len);
	
	memcpy(node->buf+hrd_size,buf,len);

	index = seq % RC_SLOT_NUM;
	if(rch->start_p == 0 && rch->end_p == 0){
		rch->start_p = rch->end_seq = index;
		rch->start_seq = rch->end_seq = seq;
	}else if(seq < rch->start_seq){
		rch->start_p = index;
		rch->start_seq = seq;
	}else if(seq > rch->end_seq){
		rch->end_p = index;
		rch->end_seq = seq;
	}else if(seq > rch->start_seq && seq < rch->end_seq){
		OSAL_trace(eRTPP, eDebug, "[%s]->[%s] rtp stream [%x] %s record_buf_add_mid seq:%d index:%u start:%d end:%d",refer->ss->f_tag,refer->ss->to_tag, 
			refer->realtime_lost.last_calc_ssrc, chan_types2str(rch->chan_type),seq,index,rch->start_p,rch->end_p);
	}else{		
		OSAL_trace(eRTPP, eWarn, "[%s]->[%s] rtp stream [%x] %s record_buf_add_err seq:%d index:%u start:%d end:%d",refer->ss->f_tag,refer->ss->to_tag, 
			refer->realtime_lost.last_calc_ssrc, chan_types2str(rch->chan_type),seq,index,rch->start_p,rch->end_p);
	}
	
	OSAL_trace(eRTPP, eDebug, "[%s]->[%s] rtp stream [%x] %s record_buf_add seq:%d index:%u start:%d end:%d",refer->ss->f_tag,refer->ss->to_tag, 
		refer->realtime_lost.last_calc_ssrc, chan_types2str(rch->chan_type),seq,index,rch->start_p,rch->end_p);

	if(rch->rcn[index].used_flag){
		if(rch->rcn[index].seq == seq){
			OSAL_trace(eRTPP, eDebug, "[%s]->[%s] rtp stream [%x] %s record_buf_add_exsit_sseq seq:%d index:%u start:%d end:%d",refer->ss->f_tag,refer->ss->to_tag, 
				refer->realtime_lost.last_calc_ssrc, chan_types2str(rch->chan_type),seq,index,rch->start_p,rch->end_p);
			osal_free(node);
			return;
		}else{
			OSAL_trace(eRTPP, eDebug, "[%s]->[%s] rtp stream [%x] %s record_buf_add_exsit_nseq nseq:%d seq:%d index:%u start:%d end:%d",refer->ss->f_tag,refer->ss->to_tag, 
				refer->realtime_lost.last_calc_ssrc, chan_types2str(rch->chan_type),rch->rcn[index].seq,seq,index,rch->start_p,rch->end_p);
			osal_free(rch->rcn[index].data);
		}
	}

	rch->rcn[index].data = node;
	rch->rcn[index].used_flag = 1;
	rch->rcn[index].seq = seq;
	
}

static void rtpp_rc_free_list(struct rc_ctr *rctr)
{
	OSAL_INT32 i;

	for(i = 0 ; i < RC_SLOT_NUM ; i++){
		if(rctr->pre.rcn[i].used_flag == 1){
			osal_free(rctr->pre.rcn[i].data);
			rctr->pre.rcn[i].data = NULL;
			rctr->pre.rcn[i].used_flag = 0;
			rctr->pre.rcn[i].seq = 0;
		}
		if(rctr->after.rcn[i].used_flag == 1){
			osal_free(rctr->after.rcn[i].data);
			rctr->after.rcn[i].data = NULL;
			rctr->after.rcn[i].used_flag = 0;
			rctr->after.rcn[i].seq = 0;
		}
	}

	rctr->pre.start_p = rctr->pre.end_p = 0;
	rctr->after.start_p = rctr->after.end_p = 0;
}

static void rtpp_rc_rewrite(struct rc_ctr *rctr)
{
	rtpp_rc_rw_ch(&rctr->after);	
	rtpp_rc_rw_ch(&rctr->pre);
}


void rtpp_rc_control(port_info_t *refer,OSAL_UINT16 lost)
{
	struct rc_ctr *rctr = refer->rcctr;

	if(!refer->fec_rec){
		return;
	}
	
	if(!rctr || rctr->init_flag == 0){
		OSAL_trace(eRTPP, eError, "rc obj not alloc or init[%p]",rctr);
		return;
	}
	
	if(lost == 0xffff){
		OSAL_trace(eRTPP, eError, "lost calc err");
		return;
	}
		
	if(rctr->start_flag == 1){
		rtpp_rc_rewrite(rctr);
		rctr->wr_times++;

		OSAL_trace(eRTPP, eInfo, "ssrc:%x fec_record_continue wr_times:%d lost:%d",
		refer->realtime_lost.last_calc_ssrc,rctr->wr_times,lost);
		
		if(rctr->wr_times == 2){
			rctr->start_flag = 0;
			rctr->wr_times = 0;
		}
		rtpp_rc_free_list(rctr);
		return;
	}

	if(lost >= 500){
		OSAL_trace(eRTPP, eInfo, "ssrc:%x fec_record_start lost:%d",
		refer->realtime_lost.last_calc_ssrc,lost);
		rtpp_rc_first(refer);
		rtpp_rc_rewrite(rctr);
		rctr->start_flag = 1;
	}
	rtpp_rc_free_list(rctr);
	
}


void rtpp_rc_end(struct rc_ctr *rcctr)
{
	if(!rcctr || rcctr->init_flag == 0)
		return;

	if(rcctr->pre.fd > 0){
		close(rcctr->pre.fd);
		rcctr->pre.fd = -1;
	}

	if(rcctr->after.fd > 0){
		close(rcctr->after.fd);
		rcctr->after.fd = -1;
	}
	rtpp_rc_free_list(rcctr);
	
	osal_free(rcctr);
	rcctr = NULL;
}
