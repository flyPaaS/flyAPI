/******************************************************************************

  Copyright (C), 2001-2011, DCN Co., Ltd.

 ******************************************************************************
  File Name     : mixer_interface.h
  Version       : Initial Draft
  Author        : gonghuojin
  Created       : 2014/2/28
  Last Modified :
  Description   : Mixer Interface Head File
  Function List :
  History       :
  1.Date        : 2014/2/28
    Author      : gonghuojin
    Modification: Created file

******************************************************************************/
#ifndef MIXER_INTERFACE_H
#define MIXER_INTERFACE_H

#ifdef __cplusplus
extern "C"
{
#endif


#ifndef IN 
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef bool_t
#define bool_t int
#endif

#ifndef RES_OK
#define RES_OK 0
#endif

#ifndef RES_ERR
#define RES_ERR -1
#endif


#define CODEC_LIST_MAX_NUM 20


/****media type****/
typedef enum media_type_t
{
	kMixer_MT_RTP    = 0,
	kMixer_MT_RTCP   = 1
}media_type_t;

/**media_data_t**/
typedef struct media_data_t
{
	media_type_t	type;
	int				slen;
	void*			data;
}media_data_t;

/*****trace level***/
typedef enum mixer_trace_level
{
	kMixer_TraceNone          = 0x0000, // no trace
	kMixer_TraceInfo          = 0x0001,
	kMixer_TraceWarning       = 0x0002,
	kMixer_TraceError         = 0x0004,
	kMixer_TraceApiCall       = 0x0010,
	kMixer_TraceStream		  = 0x0400,
	
	// used for debug purposes
	kMixer_TraceDebug         = 0x0800, // debug   
	kMixer_TraceReport		  = 0x2000, // Report	
	kMixer_TraceAll           = 0xffff
}mixer_trace_level_t;

typedef enum mixer_codec_type_t
{
	kMixer_G711U = 0,
	kMixer_G711A = 8,
	kMixer_G729 = 18,
	kMixer_SILK = 106,
	kMixer_AMR	= 107,
	kMixer_SILKWB = 115

}mixer_codec_type_t;

typedef struct mixer_participant_t
{	
	int     m_pt;	//codec payload value,see mixer_codec_type_t define
}mixer_participant_t;


typedef struct mixer_codec_list_tag
{
    int num;
    int ptlist[CODEC_LIST_MAX_NUM];
} mixer_codec_list_t;


typedef struct mixer_cfg_t
{	
	bool_t   srtp_enabled; //srtp enabled
	bool_t   bExchangeCodecFlag;  // exchange code flag
	int    max_mixers;	 //max mixer count
}mixer_cfg_t;

#define MIXER_CFG_T_SIZE (sizeof(mixer_cfg_t))

/**mixer send message  callback prototype*/
typedef int (*mixer_send_media_cb_t)(void* us_handle, int m_cnid, const media_data_t* m_data);

/**mixer trace log notification callback prototype*/
typedef void (*mixer_trace_log_cb_t)(int level, const char* logbuf, int loglen);

/**
* This structure holds all callbacks that the application should implement.
*	None is mandatory.
**/
typedef struct mixer_cb_vtable_t
{
	mixer_send_media_cb_t   send_cb;  /*msg send callback*/
	mixer_trace_log_cb_t 	log_cb;  /*notifies that call log trace */
} mixer_cb_vtable_t;


typedef struct pstatistics_t
{
	int channel_id; 	// channel id
	int codec_pt;	 	// codec payload value
    int loss_rate;  	// loss rate (network + late) in percent
    int rttMs;			// RTT Value
    int packetsSent;	// sent packets
    int packetsReceived;// received packets

}pstatistics_t;


int Mixer_init(void);

int Mixer_destroy(void);

OUT void* Mixer_create_conference(IN void* us_handle);

int Mixer_delete_conference(IN  void* mc_handle);

int Mixer_add_participant(IN  void* mc_handle, IN mixer_participant_t* pinfo);

int Mixer_remove_participant(IN  void* mc_handle,IN int participant_id);

int Mixer_recv_media(IN void* mc_handle, IN int participant_id, IN const media_data_t* m_data);

int Mixer_callback_vtable(IN  mixer_cb_vtable_t* cb_vtable);

int Mixer_trace_log_level(IN const unsigned int levelmask);

int Mixer_set_cfg(IN  mixer_cfg_t * pcfg);

int Mixer_get_cfg(OUT  mixer_cfg_t * pcfg);

int Mixer_get_statistics(IN void* mc_handle, IN int participant_id, OUT pstatistics_t* statistics);

int Mixer_do_mixer(IN void* mc_handle);

int Mixer_set_codeclist(IN void* mc_handle, IN int participant_id, IN mixer_codec_list_t *pCodecList);


#ifdef __cplusplus
}
#endif


#endif /* MIXER_INTERFACE_H */


