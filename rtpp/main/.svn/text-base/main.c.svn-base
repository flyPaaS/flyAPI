
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/ 
#include <stdio.h>
#include <stdlib.h>
#include "OSAL_types.h"
#include "OSAL_mi.h"
#include "OSAL_config.h"
#include "OSAL_diagnose.h"
#include "modules.h"
#include "rtpp_mixer.h"
#include "rtpp_http_vm.h"

OSAL_INT32 rtpp_osal_init_ok;

typedef struct
{
	const char *name;
	OSAL_moduleIdE			  id;
	OSAL_moduleInitT		  init;
	OSAL_msgHandlerT		  handle;
	OSAL_moduleEndT 		  end;
	OSAL_UINT32                io_interval; /*nomal is 0, particularly having a mass of fd to poll(select) is > 0*/
} StartModuleInfo_t;

static StartModuleInfo_t start_modules[RTPP_PTHREAD_NUM+4] = {
	{
		 "PING",
		 ePING,
		 ping_init,
		 ping_main,
		 ping_end,
	 	0,
	},
	{
		 "NOTIFY",
		 eNOTIFY,
		 notify_init,
		 notify_main,
		 notify_end,
	 	0,
	},
	{
		 "RA",
		 eRA,
		 ra_init,
		 ra_main,
		 ra_end,
	 	0,
	},
};

#define START_MODULES_COUNT (sizeof start_modules / sizeof start_modules [0])

OSAL_INT32 set_max_files (void)
{
	struct rlimit get,post;
	OSAL_INT32 ret = 0;

	ret = getrlimit(RLIMIT_NOFILE,&get);
	if(ret < 0){
		OSAL_trace(eRTPP, eError, "get RLIMIT_NOFILE %s",strerror(errno));
		return -1;
	}

	OSAL_trace(eRTPP, eSys, "get cur %d max %d",get.rlim_cur,get.rlim_max);

	post.rlim_max = 65536;
	post.rlim_cur = 65536;

	OSAL_trace(eRTPP, eSys, "first set cur %d max %d",post.rlim_cur,post.rlim_max);
	ret = setrlimit(RLIMIT_NOFILE,&post);
	if(ret < 0){
		post.rlim_max = get.rlim_max;
		post.rlim_cur = get.rlim_max;
		OSAL_trace(eRTPP, eSys, "second set cur %d max %d",post.rlim_cur,post.rlim_max);
		ret = setrlimit(RLIMIT_NOFILE,&post);
		if(ret < 0){
			OSAL_trace(eRTPP, eError, "set RLIMIT_NOFILE %s",strerror(errno));
			return -1;
		}
	}
	OSAL_trace(eRTPP, eSys, "final set RLIMIT_NOFILE c(%d) m(%d) ok",post.rlim_cur,post.rlim_max);
	return 0;
}


void set_core_dump()
{
	struct rlimit lim, newlim;

	if (getrlimit(RLIMIT_CORE, &lim)<0)
	{
		OSAL_trace( eOSAL, eWarn,"cannot get the maximum core size: %s",strerror(errno));
		return;
	}
	
	// first try max limits 
	newlim.rlim_max=RLIM_INFINITY;
	newlim.rlim_cur=newlim.rlim_max;
	if (setrlimit(RLIMIT_CORE, &newlim) ==0) 
	{
		OSAL_trace( eOSAL, eWarn,"set core dump rlim_max limits ok.");
		return;
	}
	
	// if this failed too, try rlim_max, better than nothing 
	newlim.rlim_max=lim.rlim_max;
	newlim.rlim_cur=newlim.rlim_max;
	if (setrlimit(RLIMIT_CORE, &newlim)<0)
	{
		OSAL_trace( eOSAL, eWarn,"could not increase core limits at all: %s",strerror (errno));
	}
	else
	{
		OSAL_trace( eOSAL, eWarn,"set core dump rlim_cur limits ok.");
	}
		
}

static OSAL_INT32 creat_default_file()
{
	FILE *filestream;

	filestream  = fopen(CONFIG_FILE ,"w");
	if(filestream == OSAL_NULL) {
		 printf("complete cfg file err:%s.", strerror(errno));
		 return OSAL_ERROR;
	}

	fputs("#rtpp configure file v1.0\n", filestream);
	fputs("\nRTPP_HOST_IP = 0.0.0.0\n", filestream);
	fputs("\nRTPP_COMMAND_SOCK = 0.0.0.0:7898\n", filestream);
	fputs("\nRTPP_RTPC_IP = 0.0.0.0\n", filestream);
	fputs("\nRTPP_TTL_MODE = 1	#0 ALL 1 SIDE\n", filestream);
	fputs("\nRTPP_TIMEOUT_LEN = 120\n", filestream);
	fputs("\nRTPP_RECORD_DIR = /data/record/\n", filestream);
	fputs("\nRTPP_VM_SERVER_MODE = 113.31.81.105:8686\n", filestream);
	fputs("\nPING_RATE = 15\n", filestream);
	fputs("\nPING_COLONY = 1	#0 DISABLE 1 ENABLE\n", filestream);
	fputs("\nRTPP_JT_FLAG = 0	  #0 OFF 1 ON default:OFF\n", filestream);
	fputs("\nRTPP_LOSS_RC_MODE = 0	  #0 OFF 1 ON default:OFF\n", filestream);
	fputs("\nPING_TYPE = 1	  #0 private 1 standard\n", filestream);

	fclose(filestream);
	return OSAL_OK;
}

int main( int argc,char* argv[] )
{

	int i;
	int j = eRTPP1;
	DIR *pdir = OSAL_NULL;
	
	if (!trap_exception()) {
		printf("fail to trap exception!!!");
		exit(-1);
	}
	

    OSAL_openOutput();
    OSAL_closeTraceAll();

	untrap_signal(SIGSEGV);
	set_core_dump();
	set_max_files();

	//SURE DIR IS CREAT
	if((pdir=opendir(PROFILE_PATH)) == OSAL_NULL) {
		if (errno == ENOENT){
			//mkdir (PROFILE_PATH, 755);
			char cmd[256] = {0};
			sprintf(cmd, "mkdir -p %s", PROFILE_PATH);
			system(cmd);
		}
	}
	else
		closedir(pdir);

	//SURE CONFIG FILE EXIST
	if(access(CONFIG_FILE, F_OK)) {  //not exsited
		if(OSAL_OK != creat_default_file())
			return OSAL_ERROR;
	}
	
    if (OSAL_TRUE != OSAL_init(1)){
        printf("start OSAL failed.\n");
        exit(-1);
    }
	rtpp_osal_init_ok = 1;
	
	for (i = 3; i < START_MODULES_COUNT-1; i++){
		StartModuleInfo_t *info = &start_modules[i];
		info->id = j;
		info->name = "RTPP";
		j++;
		info->init = rtpp_work_init;
		info->handle= rtpp_work_main;
		info->end= rtpp_work_end;
	}
	
	StartModuleInfo_t *info = &start_modules[i];
	info->id = eRTPP;
	info->name = "RTPP";
	info->init = rtpp_init;
	info->handle= rtpp_main;
	info->end= rtpp_end;

	/* Create all the modules. */
	for (i = 0; i < START_MODULES_COUNT; i++) {
		StartModuleInfo_t *info = &start_modules[i];
		if (OSAL_OK != OSAL_createModule(info->id, info->init, info->handle, info->end, info->io_interval))
		{
			printf ("!!! Create module %s failed !!!\n", info->name);
			exit (-1);
		}
	}
	//osal_init_shell("RtpProxy");
    rtpp_vm_init();
	syslog (3, "%s", ">>>>>>RTPP starup...>>>>>>");
	
	osal_shell_run();

    return 0;

}

static void __attribute__ ((constructor)) initso ()
{
	// We moved exec_init to main ()
}


static void __attribute__ ((destructor)) finiso ()
{
	if(Mixer_destroy() < 0){
		OSAL_trace( eRTPP, eSys, "Fail to destroy mixer");
	}
	else
		OSAL_trace( eRTPP, eSys, "mixer destroy ok");

	if(rtpp_osal_init_ok)
		osalp_shell_uninit();
	//OSAL_end ();
}


#ifdef __cplusplus
}
#endif /* __cplusplus */

