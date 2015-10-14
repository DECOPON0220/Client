#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<poll.h>
#include	<errno.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<sys/socket.h>
#include	<arpa/inet.h>
#include	<netinet/if_ether.h>
#include	"netutil.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pthread.h>
#include "myprotocol.h"

#define MAXSIZE 8192

// DEVICE NAME
char *NameDev1="wlan1";
char *NameDev2="eth0";

typedef struct	{
  int	soc;
}DEVICE;
DEVICE	Device[2];

int DebugOut=0;
int EndFlag=0;
int StaFlag=0;   // 0: Discover
                 // 1: Request
struct ifreq Device1;
struct ifreq Device2;

int DebugPrintf(char *fmt,...)
{
  if(DebugOut){
    va_list	args;

    va_start(args,fmt);
    vfprintf(stderr,fmt,args);
    va_end(args);
  }

  return(0);
}

int DebugPerror(char *msg)
{
  if(DebugOut){
    fprintf(stderr,"%s : %s\n",msg,strerror(errno));
  }

  return(0);
}

void make_ethernet(struct ether_header *eth, unsigned char *ether_dhost,
		unsigned char *ether_shost, u_int16_t ether_type) {
	memcpy(eth->ether_dhost, ether_dhost, 6);
	memcpy(eth->ether_shost, ether_shost, 6);
	eth->ether_type = htons(ether_type);
}

void make_mydhcp(struct myprotocol *myproto) {
  myproto->ip_src = inet_addr("00H.00H.00H.00H");
  myproto->ip_dst = inet_addr("FF.FF.FF.FFH");
  myproto->type = htons(DISCOVER);
}


void create_myprotocol (int soc) {
  char *sp;
  char send_buff[MAXSIZE];
  u_char smac_addr[6];
  u_char dmac_addr[6];

  int tmp_dmac[6];
  char *dmac = "ff:ff:ff:ff:ff:ff";

  sp = send_buff + sizeof(struct ether_header);

  if (sscanf(dmac, "%x:%x:%x:%x:%x:%x", &tmp_dmac[0], &tmp_dmac[1], &tmp_dmac[2], &tmp_dmac[3],
	     &tmp_dmac[4], &tmp_dmac[5]) != 6) {
    printf("MAC address error %s\n", dmac);
  }
  
  int i;
  for (i = 0; i < 6; i++) smac_addr[i] = (char) Device1.ifr_hwaddr.sa_data[i];
  for (i = 0; i < 6; i++) dmac_addr[i] = (char) tmp_dmac[i];
  
  make_mydhcp((struct myprotocol *) sp);
  make_ethernet((struct ether_header *) send_buff, dmac_addr, smac_addr, DISCOVER);

  int len;
  len = sizeof(struct ether_header) + sizeof(struct myprotocol);
  if (write(soc, send_buff, len) < 0) {
    perror("write");
  }
}

int AnalyzePacket(int deviceNo,u_char *data,int size)
{
  u_char	*ptr;
  int	lest;
  struct ether_header	*eh;

  ptr=data;
  lest=size;

  if(lest<sizeof(struct ether_header)){
    DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,lest);
    return(-1);
  }
  eh=(struct ether_header *)ptr;
  ptr+=sizeof(struct ether_header);
  lest-=sizeof(struct ether_header);
  DebugPrintf("[%d]",deviceNo);
  if(DebugOut){
    PrintEtherHeader(eh,stderr);
  }

  return(0);
}

int changeIPAddr(u_int32_t ip)
{
  int fd;
  struct ifreq ifr;
  struct sockaddr_in *s_in;

  fd=socket(AF_INET, SOCK_DGRAM, 0);

  s_in = (struct sockaddr_in *)&ifr.ifr_addr;
  s_in->sin_family = AF_INET;
  s_in->sin_addr.s_addr = ip;

  strncpy(ifr.ifr_name, Device1.ifr_name, IFNAMSIZ-1);

  if (ioctl(fd, SIOCSIFADDR, &ifr) != 0) {
    perror("ioctl");
  }

  printf("Change IP Address: %s\n", inet_ntoa(*(struct in_addr*)&ip));

  close(fd);
  return(0);
}

int chkMyProtocol(u_char *data, int size)
{
  u_char *ptr;
  int lest;
  struct ether_header *eh;
  struct myprotocol *myproto;
  ptr=data;
  lest=size;
  char sMACaddr[18];
  char dMACaddr[18];
  char myMACaddr[18];
  u_char mymac_addr[6];
  int flg=0;

  eh=(struct ether_header *)ptr;
  ptr+=sizeof(struct ether_header);
  lest-=sizeof(struct ether_header);

  my_ether_ntoa_r(eh->ether_shost, sMACaddr, sizeof(sMACaddr));
  my_ether_ntoa_r(eh->ether_dhost, dMACaddr, sizeof(dMACaddr));

  int i;
  for (i = 0; i < 6; i++) mymac_addr[i] = (char) Device1.ifr_hwaddr.sa_data[i];
  my_ether_ntoa_r(mymac_addr, myMACaddr, sizeof(sMACaddr));

  if((strncmp(dMACaddr, myMACaddr, 18) == 0) &&
     (ntohs(eh->ether_type) == OFFER)) {
    printf("Receive Offer Packet\n");

    myproto = (struct myprotocol *) ptr;
    ptr += sizeof(struct myprotocol);
    lest -= sizeof(struct myprotocol);
    
    changeIPAddr(myproto->ip_dst);

    return(1);
  }

  return(0);
}

int chkOffer ()
{
  struct pollfd target[1];
  int size;
  u_char buf[2048];

  target[0].fd=Device[0].soc;
  target[0].events=POLLIN|POLLERR;
  
  while(EndFlag==0){
    if(poll(target,1,100)<0){
      if(errno!=EINTR){
	perror("poll");
      }
      break;
    } else {
      if(target[0].revents&(POLLIN|POLLERR)){
	if((size=read(Device[0].soc,buf,sizeof(buf)))<=0){
	  perror("read");
	}

	if(chkMyProtocol(buf, size) == 1){
	  printf("test\n");
	  StaFlag=1;
	}
      }
    }
  }
  
  return(0);
}

int Bridge()
{
  struct pollfd	targets[2];
  int	nready,i,size;
  u_char	buf[2048];

  targets[0].fd=Device[0].soc;
  targets[0].events=POLLIN|POLLERR;
  targets[1].fd=Device[1].soc;
  targets[1].events=POLLIN|POLLERR;

  while(EndFlag==0){
    if (StaFlag==0) {
      printf("Send Discover Packet\n");
      create_myprotocol(Device[0].soc);

      usleep(10000 * 100);
    } else if (StaFlag==1) {
      
    }
  }

  return(0);
}

int DisableIpForward()
{
  FILE    *fp;

  if((fp=fopen("/proc/sys/net/ipv4/ip_forward","w"))==NULL){
    DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
    return(-1);
  }
  fputs("0",fp);
  fclose(fp);

  return(0);
}

void EndSignal(int sig)
{
  EndFlag=1;
}

struct ifreq getIFInfo (char *device) {
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, device, IFNAMSIZ-1);

  ioctl(fd, SIOCGIFHWADDR, &ifr);

  close(fd);

  printf("Get \"%s\" Info\n", device);
  return ifr;
}

void *thread1 (void *args) {
  printf("Create Threat1\n");
  Bridge();
  return NULL;
}

void *thread2 (void *args) {
  printf("Create Threat2\n");
  //chkOffer();
  return NULL;
}

int main(int argc,char *argv[],char *envp[])
{
  pthread_t th1, th2;

  // Get Interface Infomation
  Device1 = getIFInfo(NameDev1);
  Device2 = getIFInfo(NameDev2);
  
  if((Device[0].soc=InitRawSocket(Device1.ifr_name,1,0))==-1){
    DebugPrintf("InitRawSocket:error:%s\n",Device1);
    return(-1);
  }
  DebugPrintf("%s OK\n",Device1);

  if((Device[1].soc=InitRawSocket(Device2.ifr_name,1,0))==-1){
    DebugPrintf("InitRawSocket:error:%s\n",Device1);
    return(-1);
  }
  DebugPrintf("%s OK\n",Device2);

  DisableIpForward();

  signal(SIGINT,EndSignal);
  signal(SIGTERM,EndSignal);
  signal(SIGQUIT,EndSignal);

  signal(SIGPIPE,SIG_IGN);
  signal(SIGTTIN,SIG_IGN);
  signal(SIGTTOU,SIG_IGN);

  DebugPrintf("bridge start\n");
  int status;
  if ((status = pthread_create(&th1, NULL, thread1, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }
  if ((status = pthread_create(&th2, NULL, thread2, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }

  DebugPrintf("bridge end\n");

  pthread_join(th1, NULL);
  pthread_join(th2, NULL);

  close(Device[0].soc);
  close(Device[1].soc);

  return(0);
}
