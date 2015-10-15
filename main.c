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
#define SIZE_MAC 18
#define SIZE_IP 15

// DEVICE NAME
const char *NameDev1="wlan1";
const char *NameDev2="eth0";



typedef struct	{
  int	soc;
}DEVICE;
DEVICE	Device[2];

int DebugOut=0;
int EndFlag=0;
int StatusFlag=1;   // 0: Stop 1: Discover 2:Request

char hostMacAddr[SIZE_MAC];
char dev1MacAddr[SIZE_MAC];
char dev2MacAddr[SIZE_MAC];
char dev1IpAddr[SIZE_IP];
char dev2IpAddr[SIZE_IP];

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

void make_mydhcp(struct myprotocol *myproto, char *sip, char *dip, u_short type) {
  myproto->ip_src = inet_addr(sip);
  myproto->ip_dst = inet_addr(dip);
  myproto->type = htons(type);
}


void create_myprotocol (int soc, char *smac, char *dmac, char *sip, char *dip, u_short type) {
  char *sp;
  char send_buff[MAXSIZE];
  u_char smac_addr[6];
  u_char dmac_addr[6];

  sp = send_buff + sizeof(struct ether_header);

  my_ether_aton_r(smac, smac_addr);
  my_ether_aton_r(dmac, dmac_addr);
  
  make_mydhcp((struct myprotocol *) sp, sip, dip, type);
  make_ethernet((struct ether_header *) send_buff, dmac_addr, smac_addr, type);

  int len;
  len = sizeof(struct ether_header) + sizeof(struct myprotocol);
  if (write(soc, send_buff, len) < 0) {
    perror("write");
  }
}

int sendMyProtocol(int deviceNo)
{
  while(EndFlag==0){
    if(StatusFlag==1){
      printf("Send Discover Packet\n");
      
      char *dmac = "ff:ff:ff:ff:ff:ff";
      char *sip = "00H.00H.00H.00H";
      char *dip = "FF.FF.FF.FF";
      create_myprotocol(Device[deviceNo].soc, dev1MacAddr, dmac, sip, dip, DISCOVER);
      
      usleep(10000 * 100);
    }
  }

  
    
  return(0);
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

int changeIPAddr(const char *device, u_int32_t ip)
{
  int fd;
  struct ifreq ifr;
  struct sockaddr_in *s_in;

  fd=socket(AF_INET, SOCK_DGRAM, 0);

  s_in = (struct sockaddr_in *)&ifr.ifr_addr;
  s_in->sin_family = AF_INET;
  s_in->sin_addr.s_addr = ip;

  strncpy(ifr.ifr_name, device, IFNAMSIZ-1);

  if (ioctl(fd, SIOCSIFADDR, &ifr) != 0) {
    perror("ioctl");
  }

  close(fd);
  return(0);
}

/*
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
  my_ether_aton_r(dev1MacAddr, mymac_addr);
  my_ether_ntoa_r(mymac_addr, myMACaddr, sizeof(sMACaddr));

  if((strncmp(dMACaddr, myMACaddr, 18) == 0) &&
     (ntohs(eh->ether_type) == OFFER)) {
    printf("Receive Offer Packet\n");

    myproto = (struct myprotocol *) ptr;
    ptr += sizeof(struct myprotocol);
    lest -= sizeof(struct myprotocol);
    
    changeIPAddr(NameDev1, myproto->ip_dst);

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
*/

int Bridge()
{

  while(EndFlag==0){
    
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

void getIfInfo (const char *device, struct ifreq *ifreq, int flavor)
{
  int fd;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  memset(ifreq, '\0', sizeof(*ifreq));
  strcpy(ifreq->ifr_name, device);
  ioctl(fd, flavor, ifreq);
  close(fd);
}

void getIfMac (const char *device, char *macAddr)
{
  struct ifreq ifreq;
  u_char tmpAddr[6];

  getIfInfo(device, &ifreq, SIOCGIFHWADDR);
  
  int i;
  for(i=0;i<6;i++) tmpAddr[i]=(char)ifreq.ifr_hwaddr.sa_data[i];
  my_ether_ntoa_r(tmpAddr, macAddr, SIZE_MAC);
}

void getIfIp (const char *device, char *ipAddr)
{
  struct ifreq ifreq;
  
  getIfInfo(device, &ifreq, SIOCGIFADDR);
  memcpy(ipAddr, inet_ntoa(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr), SIZE_IP);
}

void *thread1 (void *args) {
  printf("Create Threat1\n");
  //Bridge();
  return NULL;
}

void *thread2 (void *args) {
  printf("Create Threat2\n");
  sendMyProtocol(0);
  return NULL;
}

int main(int argc,char *argv[],char *envp[])
{
  pthread_t th1, th2;

  // Get Interface Infomation
  getIfMac(NameDev1, dev1MacAddr);
  getIfIp(NameDev1, dev1IpAddr);
  getIfMac(NameDev2, dev2MacAddr);
  getIfIp(NameDev2, dev2IpAddr);
  
  // Init Soc
  if((Device[0].soc=InitRawSocket(NameDev1,1,0))==-1){
    DebugPrintf("InitRawSocket:error:%s\n",NameDev1);
    return(-1);
  }
  DebugPrintf("%s OK\n",NameDev1);

  if((Device[1].soc=InitRawSocket(NameDev2,1,0))==-1){
    DebugPrintf("InitRawSocket:error:%s\n",NameDev2);
    return(-1);
  }
  DebugPrintf("%s OK\n",NameDev2);

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
