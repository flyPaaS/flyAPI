
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <poll.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <sys/syscall.h>
#include "rtpp_main.h"

//static char vm_local_ip[16] = "127.0.0.1";
//static short vm_local_port = 10080;
#include "rtpp_session.h"
#include "rtpp_http_vm.h"


extern OSAL_CHAR ghttpVmServerIp[MAX_IP_LEN];
extern OSAL_INT32 ghttpVmServerPort;
extern OSAL_CHAR ghttpVmCfgReloaded;
extern rtpp_hash_table rtpp_hash_tbl;

int vm_create_sock(char *ip, short port,int sock_type,int proto)
{
    struct sockaddr_in serv_addr;
    int  buffSize = 4096 * 1024 * 2;
    int  sock = -1;
    int  optval;

    if ((sock = socket(AF_INET, sock_type, proto)) < 0) {
    	OSAL_trace (eRTPP, eError, "socket err: %s.", strerror(errno));
        return -1;
    }
	
	optval=1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR ,(void*)&optval, sizeof(optval)) == -1){
    	OSAL_trace (eRTPP, eError, "setsockopt SO_REUSEADDR err: %s.", strerror(errno));
        return -1;
	}
	
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize)) < 0) {
    	OSAL_trace (eRTPP, eError, "setsockopt SO_RCVBUF err: %s.", strerror(errno));
        close(sock);
        return -1;
    }
	
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffSize, sizeof(buffSize)) < 0){
    	OSAL_trace (eRTPP, eError, "setsockopt SO_RCVBUF err: %s.", strerror(errno));
        close(sock);
        return -1;
    }

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_port        = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr(ip);

    if (bind(sock,(struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    	OSAL_trace (eRTPP, eError, "bind ip:%s,port:%d err: %s.", ip,port,strerror(errno));
        close(sock);
        return -1;
    }
    OSAL_trace (eRTPP, eInfo, "create %s socket OK!ip:%s,port:%d.",sock_type == SOCK_STREAM ? "tcp":"udp",ip,port);

    return sock;
}

void * vm_client_proc(void * arg)
{
	int fd;
	ssize_t n;
	char buff[1024];
	char respone[1024];
	size_t buf_len=1024;
	struct pollfd pfd = {0};
	fd = *((int*)arg);
	int ret;
    
	pfd.fd = fd;
	pfd.events = POLLIN|POLLPRI;
	ret = poll(&pfd,1,5000);
	if(ret>0){
		n = read(fd,buff,buf_len);
		if(n <= 0)
		{
            OSAL_trace (eRTPP, eError, "vm client read err: %s.", strerror(errno));
			close(fd);
			return;
		}
		buff[n] = 0;

		n = snprintf(respone,1024,"HTTP/1.1 200 OK\r\n"
		"Server:SIPEX.VM\r\n"
		"Content-Type:text/javascript;charset=utf-8\r\n"
		"Connection:close\r\n\r\n%u\r\n",rtpp_hash_tbl.used);
		OSAL_trace (eRTPP, eSys, "rtpp http concurrent %u",rtpp_hash_tbl.used);
		ret = write(fd,respone,n);
		if(ret != n){
			if(ret < 0)
                OSAL_trace (eRTPP, eError, "vm client write err: %s.", strerror(errno));
			else
                OSAL_trace (eRTPP, eInfo, "vm client write %d[%d]", ret,n);
		}
	}else if(ret==0){
        OSAL_trace (eRTPP, eError, "vm poll timeout");
	}else{
        OSAL_trace (eRTPP, eError, "vm poll err: %s.", strerror(errno));
	}
	close(fd);
	pthread_exit(0);
	return;
}


int rtpp_vm_http()
{
	//
	int fd = 0;
	int client_fd = 0;
	struct sockaddr_in faddr;
	socklen_t faddrlen = sizeof(faddr);
	pthread_t j;
	struct pollfd pfd = {0};
	int ret;

	/*第一次启动时使用配置，如果没有，则不使用默认值*/
	//if('\0' != CtgwGlobals.vm_ip[0])
	//	strcpy(vm_local_ip,CtgwGlobals.vm_ip);
	//if(0 != CtgwGlobals.vm_port)
	//	vm_local_port=CtgwGlobals.vm_port;

reload:

	fd = vm_create_sock(ghttpVmServerIp,ghttpVmServerPort,SOCK_STREAM,IPPROTO_TCP);
	if(fd < 0)
	{
        OSAL_trace (eRTPP, eError, "create sock failed ip %s port %d",ghttpVmServerIp, ghttpVmServerPort);
		return -1;
	}

	listen(fd,10);

    OSAL_trace (eRTPP, eInfo, "vm http server pid[%d] ip[%s] port[%d] start ok.......!!!",syscall(__NR_gettid),ghttpVmServerIp,ghttpVmServerPort);
    //printf ("vm http server pid[%d] ip[%s] port[%d] start ok.......!!!",syscall(__NR_gettid),vm_local_ip,vm_local_port);
	while(1){
again:
		pfd.fd = fd;
		pfd.events = POLLIN|POLLPRI;
		ret = poll(&pfd,1,1000);
		if(ret < 0){
			if (errno == EINTR){
				goto again;
			}else{
                OSAL_trace (eRTPP, eError, "vm main poll fail:%s,pthread exit",strerror(errno));
				pthread_exit(-1);
			}
		}
		//配置有加载
		
       // OSAL_trace (eRTPP, eInfo, "*****CtgwGlobals.vm_cfg_reloaded %d*******", CtgwGlobals.vm_cfg_reloaded);
		if(ghttpVmCfgReloaded){
        	ghttpVmCfgReloaded = 0;
			
			//配置有变化
			close(fd);
			goto reload;
		}else{
                //OSAL_trace (eRTPP, eInfo, "*****vm config not update*******");
        }
		if(ret >0){
			client_fd =  accept(fd,(struct sockaddr*)&faddr,&faddrlen);
			if(client_fd < 0){
                OSAL_trace (eRTPP, eError, "accept failed:%s",strerror(errno));
				return (-1);
			}
            OSAL_trace (eRTPP, eInfo, "accept client %s:%d ok",inet_ntoa(faddr.sin_addr),ntohs(faddr.sin_port));
			if(pthread_create(&j,NULL,vm_client_proc,(void *)&client_fd)!=0){
                OSAL_trace (eRTPP, eError, "pthread_create failed:%s",strerror(errno));
			}else{
			    //与主线程分离
				pthread_detach(j);
			}
		}
	}
	
	pthread_exit(0);
}

int rtpp_vm_init()
{
	pthread_t j;

	pthread_create(&j,NULL,rtpp_vm_http,NULL);
}


