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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "mydef.h"
#include "mystruct.h"
#include "myprotocol.h"
#include "checksum.h"
#include "ifutil.h"
//#include "rewrite.h"



// DEVICE NAME
char *testmac="ff:ff:ff:ff:ff:ff";

const char *NameDev1="wlan1";
const char *NameDev2="wlan2";
const char *NameDev3="eth0";

const char *apEssId="test_ap";
const char *filename="myap.dat";



INFOAP mainAP;
INFOAP subAP;

int DebugOut=0;
int EndFlag=0;
int StatusFlag=1;
int ClientMacFlag=0;
int ScanFlag=0;
int MainDev=0;

char apMacAddr[SIZE_MAC];
char apIpAddr[SIZE_IP];
char cliMacAddr[SIZE_MAC];
char *cliIpAddr="192.168.100.11";
char dev1MacAddr[SIZE_MAC];
char dev2MacAddr[SIZE_MAC];
char dev3MacAddr[SIZE_MAC];
char dev1IpAddr[SIZE_IP];
char dev2IpAddr[SIZE_IP];
char *dev3IpAddr="192.168.100.1";



INFOAP *getMyApInfo(const char* file, int numAP, INFOAP *tmpAP);
int getNumMyAP(const char* file);

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

int getMaxIndex(INFOAP *myap, int numMyAp)
{
  int i;
  int maxIndex;
  int maxQual;

  maxQual=myap[0].Qual;
  
  if(numMyAp>1){
    for(i=1;i<numMyAp;i++){
      if(maxQual>myap[i].Qual){
	maxQual=myap[i].Qual;
	maxIndex=i;
      }
    }
  }

  return(maxIndex);
}

int sendMyProtocol(int deviceNo)
{
  int numMyAp;
  int maxIndex;

  numMyAp=getNumMyAP(filename);
  INFOAP InfoMyAp[numMyAp];
  
  if(numMyAp==0){
    return(0);
  }

  getMyApInfo(filename, numMyAp, InfoMyAp);
  //printf("infoMyAp[0].MacAddr: %s\n", InfoMyAp[0].MacAddr);
  //printf("infoMyAp[1].MacAddr: %s\n", InfoMyAp[1].MacAddr);
  //printf("infoMyAp[0].Qual: %d\n", InfoMyAp[0].Qual);
  //printf("infoMyAp[1].Qual: %d\n", InfoMyAp[1].Qual);
  
  maxIndex=getMaxIndex(InfoMyAp, numMyAp);
  //printf("maxIndex: %d\n", maxIndex);

  if(StatusFlag==1){
    printf("Send Discover Packet\n");
    
    //char *dmac = "ff:ff:ff:ff:ff:ff";
    char *sip = "00H.00H.00H.00H";
    char *dip = "FF.FF.FF.FF";
    create_myprotocol(Device[deviceNo].soc, dev1MacAddr, InfoMyAp[maxIndex].MacAddr, sip, dip, DISCOVER);
    //create_myprotocol(Device[deviceNo].soc, dev1MacAddr, dmac, sip, dip, DISCOVER);

    usleep(10000 * 100);
  } else if(StatusFlag==2){
    printf("Send Approval Pakcet\n");
    
    create_myprotocol(Device[deviceNo].soc, dev1MacAddr, InfoMyAp[1].MacAddr, dev1IpAddr, apIpAddr, APPROVAL);

    StatusFlag=3;
  }

  return(0);
}

/*
int chkMyProtocol()
{
  
}
*/

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

  // Get Client Mac Address
  if(ClientMacFlag==0){
    if(ntohs(eh->ether_type)==ETHERTYPE_IP){
      struct iphdr *iphdr;
      
      iphdr=(struct iphdr *)ptr;
      ptr+=sizeof(struct iphdr);
      lest-=sizeof(struct iphdr);

      if(strncmp(cliIpAddr, inet_ntoa(*(struct in_addr *)&iphdr->saddr), SIZE_IP)==0){
        my_ether_ntoa_r(eh->ether_shost, cliMacAddr, sizeof(cliMacAddr));	
	ClientMacFlag=1;
      }
    }
  }

  // Check My Protocol
  if(StatusFlag==1) {
    char sMACaddr[18];
    char dMACaddr[18];
    
    my_ether_ntoa_r(eh->ether_shost, sMACaddr, sizeof(sMACaddr));
    my_ether_ntoa_r(eh->ether_dhost, dMACaddr, sizeof(dMACaddr));
    memcpy(apMacAddr, sMACaddr, sizeof(sMACaddr));

    if(strncmp(dMACaddr, dev1MacAddr, SIZE_MAC)==0 &&
       ntohs(eh->ether_type)==OFFER){
      MYPROTO *myproto;
      
      printf("Recieve Offer Packet\n");
      myproto=(MYPROTO *) ptr;
      ptr+=sizeof(MYPROTO);
      lest-=sizeof(MYPROTO);

      if(ntohs(myproto->type)==OFFER){
        memcpy(dev1IpAddr, inet_ntoa(*(struct in_addr *)&myproto->ip_dst), SIZE_IP);
	memcpy(apIpAddr, inet_ntoa(*(struct in_addr *)&myproto->ip_src), SIZE_IP);
	
	if(chgIfIp(NameDev1, myproto->ip_dst)==0){
	  StatusFlag=2;
	  return(-1);
	}
      }
    }
  }

  return(0);
}

int RewritePacket (int deviceNo, u_char *data, int size)
{
  u_char *ptr;
  struct ether_header *eh;
  int lest, len;
  
  ptr=data;
  lest=size;
  
  if(lest<sizeof(struct ether_header)){
    DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,lest);
    return(-1);
  }

  eh=(struct ether_header *)ptr;
  ptr+=sizeof(struct ether_header);
  lest-=sizeof(struct ether_header);

  char dMACaddr[18];
  char sMACaddr[18];
  
  // Get dMAC, sMAC
  my_ether_ntoa_r(eh->ether_dhost, dMACaddr, sizeof(dMACaddr));
  my_ether_ntoa_r(eh->ether_shost, sMACaddr, sizeof(sMACaddr));
  
  // wirelessNIC -> physicalNIC
  if(deviceNo==0){
    my_ether_aton_r(dev3MacAddr, eh->ether_shost);
    if(strncmp(dMACaddr, dev1MacAddr, SIZE_MAC)==0){
      my_ether_aton_r(cliMacAddr, eh->ether_dhost);
    }

    // Case: IP
    if (ntohs(eh->ether_type)==ETHERTYPE_IP) {
      struct iphdr *iphdr;
      u_char option[1500];
      int optLen;
	
      iphdr=(struct iphdr *)ptr;
      ptr+=sizeof(struct iphdr);
      lest-=sizeof(struct iphdr);
      
      optLen=iphdr->ihl*4-sizeof(struct iphdr);
      
      if(optLen>0){
	memcpy(option, ptr, optLen);
	ptr+=optLen;
	lest-=optLen;
      }
      
      // Rewrite IP Address
      if(iphdr->saddr==inet_addr(apIpAddr)){
	iphdr->saddr=inet_addr(dev3IpAddr);
      }
      if(iphdr->daddr==inet_addr(dev1IpAddr)){
	iphdr->daddr=inet_addr(cliIpAddr);
      }
      
      iphdr->check=0;
      iphdr->check=calcChecksum2((u_char *)iphdr, sizeof(struct iphdr), option, optLen);

      // Case : TCP
      if(iphdr->protocol==IPPROTO_TCP){
	struct tcphdr *tcphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	tcphdr=(struct tcphdr *)ptr;

	tcphdr->check=0;
	tcphdr->check=checkIPDATAchecksum(iphdr, ptr, len);
      }
      // Case : UDP
      if(iphdr->protocol==IPPROTO_UDP){
	struct udphdr* udphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	udphdr=(struct udphdr *)ptr;
	udphdr->check=0;
      }
    }

    // physicalNIC -> wirelessNIC
  } else if(deviceNo==1){
    // Rewrite MAC Address
    my_ether_aton_r(dev1MacAddr, eh->ether_shost);
    if(strncmp(dMACaddr, dev3MacAddr, SIZE_MAC)==0){
      my_ether_aton_r(apMacAddr,eh->ether_dhost);
    }

    // Case: IP
    if (ntohs(eh->ether_type)==ETHERTYPE_IP) {
      struct iphdr *iphdr;
      u_char option[1500];
      int optLen;
	
      iphdr=(struct iphdr *)ptr;
      ptr+=sizeof(struct iphdr);
      lest-=sizeof(struct iphdr);
      
      optLen=iphdr->ihl*4-sizeof(struct iphdr);
      
      if(optLen>0){
	memcpy(option, ptr, optLen);
	ptr+=optLen;
	lest-=optLen;
      }
      
      // Rewrite IP Address
      if(iphdr->saddr==inet_addr(cliIpAddr)){
	iphdr->saddr=inet_addr(dev1IpAddr);
      }
      if(iphdr->daddr==inet_addr(dev3IpAddr)){
	iphdr->daddr=inet_addr(apIpAddr);
      }
       
      iphdr->check=0;
      iphdr->check=calcChecksum2((u_char *)iphdr, sizeof(struct iphdr), option, optLen);

      // Case : TCP
      if(iphdr->protocol==IPPROTO_TCP){
	struct tcphdr *tcphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	tcphdr=(struct tcphdr *)ptr;

	tcphdr->check=0;
	tcphdr->check=checkIPDATAchecksum(iphdr, ptr, len);
      }
      // Case : UDP
      if(iphdr->protocol==IPPROTO_UDP){
	struct udphdr* udphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	udphdr=(struct udphdr *)ptr;
	udphdr->check=0;
      }
    }
  }

  return(0);
}

int Bridge()
{
  struct pollfd targets[3];
  int nready,i,size;
  u_char buf[2048];

  targets[0].fd=Device[0].soc;
  targets[0].events=POLLIN|POLLERR;
  targets[1].fd=Device[1].soc;
  targets[1].events=POLLIN|POLLERR;
  targets[1].fd=Device[2].soc;
  targets[1].events=POLLIN|POLLERR;

  while(EndFlag==0){
    if(ScanFlag!=0){
      switch(nready=poll(targets,3,100)){
      case	-1:
	if(errno!=EINTR){
	  perror("poll");
	}
	break;
      case	0:
	break;
      default:
	for(i=0;i<3;i=i+2){
	  if(targets[i].revents&(POLLIN|POLLERR)){
	    if((size=read(Device[i].soc,buf,sizeof(buf)))<=0){
	      perror("read");
	    }
	    else{
	      if(AnalyzePacket(i,buf,size)!=-1 && RewritePacket(i,buf,size)!=-1){
		if(i==0){
		  if((size=write(Device[2].soc,buf,size))<=0){
		    //perror("write");
		  }
		}else if(i==2){
		  if((size=write(Device[0].soc,buf,size))<=0){
		    //perror("write");
		  }
		}
	      }
	    }
	  }
	}
	break; 
      }
    }
  }
  return(0);
}

int getNumAP(const char* file){
  FILE *fp;
  char buf[256];
  int numLine = 0;    // Line number of 'ap.dat'
  int numAP;

  // Get the lines of 'ap.dat'
  if ((fp=fopen(file, "r")) == NULL){
    perror("FILE Open error");
  }
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    numLine++;
  }
  
  numAP = ((numLine - 1) / 3);
  
  return numAP;
}

int getNumMyAP(const char* file){
  FILE *fp;
  char buf[256];
  int numLine = 0;    // Line number of 'ap.dat'
  int numAP;

  // Get the lines of 'ap.dat'
  if ((fp=fopen(file, "r")) == NULL){
    perror("FILE Open error");
  }
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    numLine++;
  }
  
  numAP = numLine / 2;

  return numAP;
}

INFOAP *getAPInfo(const char* file, int numAP, INFOAP *tmpAP){
  FILE *fp;
  char buf[256];
  const char *Addr = "          Cell";
  const char *Qual = "                    Quality";
  const char *Ssid = "                    ESSID";
  int cmpAddr = 13;    // For comparison
  int cmpQual = 26;
  int cmpSsid = 24;
  int plAddr, plQual, plSsid;
  int calcAP, tmpNum;

  // Get the information of AP
  fp=fopen(file, "r");
  calcAP = 0;
  while (fgets(buf, sizeof(buf), fp) != NULL && calcAP < numAP) {
    tmpNum = 0;
    // Get Address 
    if (strncmp(buf, Addr, cmpAddr) == 0) {
      plAddr = 29;
      while (buf[plAddr] != '\n') {
	tmpAP[calcAP].MacAddr[tmpNum] = buf[plAddr];
	tmpNum++;
	plAddr++;
      }
      tmpAP[calcAP].MacAddr[tmpNum] = '\0';    // final char
    }
    // Get Quality - 49
    if (strncmp(buf, Qual, cmpQual) == 0) {
      char tmpChar[2];
      plQual = 49;

      tmpChar[tmpNum] = buf[plQual];
      tmpNum++;
      plQual++;

      if(buf[plQual]==' '){
        tmpChar[tmpNum] = '\0';
      }else{
	tmpChar[tmpNum] = buf[plQual];
      }
      tmpAP[calcAP].Qual = atoi(tmpChar);
    }
    // Get Quality - 27
    if (strncmp(buf, Ssid, cmpSsid) == 0) {
      plSsid = 27;
      while (buf[plSsid] != '\"') {
	tmpAP[calcAP].ESSID[tmpNum] = buf[plSsid];
	tmpNum++;
	plSsid++;
      }
      tmpAP[calcAP].ESSID[tmpNum] = '\0';    // final char

      calcAP++;
    }
  }

  fclose(fp);
  return tmpAP;
}

INFOAP *getMyApInfo(const char* file, int numAP, INFOAP *tmpAP)
{
  FILE *fp;
  char buf[256];
  const char *Addr = "Address : ";
  const char *Qual = "Quality : ";
  int cmpAddr = 10;    // For comparison
  int cmpQual = 10;
  int plAddr, plQual;
  int calcAP, tmpNum;
  
  // Get the information of AP
  fp=fopen(file, "r");
  calcAP = 0;
  while (fgets(buf, sizeof(buf), fp) != NULL && calcAP < numAP) {
    tmpNum = 0;
    // Get Address 10
    if (strncmp(buf, Addr, cmpAddr) == 0) {
      plAddr = 10;
      while (buf[plAddr] != '\n') {
	tmpAP[calcAP].MacAddr[tmpNum] = buf[plAddr];
	tmpNum++;
	plAddr++;
      }
      tmpAP[calcAP].MacAddr[tmpNum] = '\0';    // final char
    }
    // Get Quality - 10
    if (strncmp(buf, Qual, cmpQual) == 0) {
      char tmpChar[2];
      plQual = 10;

      tmpChar[tmpNum] = buf[plQual];
      tmpNum++;
      plQual++;
      
      if(buf[plQual]==' '){
	tmpChar[tmpNum] = '\0';
      }else{
	tmpChar[tmpNum] = buf[plQual];
      }
      tmpAP[calcAP].Qual = atoi(tmpChar);

      calcAP++;
    }
  }

  fclose(fp);
  return tmpAP;
}

int scanAp()
{
  FILE *result, *fp;
  const char *tmpfile = "tmp.dat";
  const char *tmpcmd = "iwlist %s scan | egrep 'Cell |ESSID|Quality'";
  char cmdline[64];

  INFOAP *infoAp;    // For storing AP info
  int numAP;

  while(EndFlag==0){
    if(MainDev==0){
      sprintf(cmdline, tmpcmd, NameDev2);
    }else if(MainDev==1){
      sprintf(cmdline, tmpcmd, NameDev1);
    }

    if ((result=popen(cmdline, "r")) == NULL){
      perror ("Command error");
    }

    char buf[256];

    // Overwride AP data in 'ap.dat'
    //printf("Start '%s' update.\n", filename);
    if ((fp=fopen(tmpfile, "w")) == NULL){
      perror ("File Open error");
    }
    while(!feof(result)){
      fgets(buf, sizeof(buf), result);
      fputs(buf, fp);
    }
    //printf("Finish '%s' update.\n", filename);
    fclose(fp);
    (void) pclose(result);
    
    // Get the information of AP
    numAP = getNumAP(tmpfile);
    INFOAP tmpInfoAP[numAP];
    infoAp = getAPInfo(tmpfile, numAP, tmpInfoAP);

    // Write My Access Point
    // Reset
    if ((fp=fopen(filename, "w")) == NULL){
      perror ("File Open error");
    }
    fclose(fp);
    if ((fp=fopen(filename, "a")) == NULL){
      perror ("File Open error");
    }
    int i;
    for(i=0;i<numAP;i++){
      if(strcmp(infoAp[i].ESSID, apEssId)==0){
	fprintf(fp, "Address : %s\n", infoAp[i].MacAddr);
	fprintf(fp, "Quality : %d\n", infoAp[i].Qual);
      }
    }
    fclose(fp);
 
    if(ScanFlag==0){
      ScanFlag=1;
    }

    sleep(5);
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

void *thread1(void *args)
{
  printf("Create Thread1\n");
  Bridge();
  return NULL;
}

void *thread2(void *args)
{
  printf("Create Thread2\n");
  while(EndFlag==0){
    if(ScanFlag!=0){
      sendMyProtocol(MainDev);
    }
  }
  return NULL;
}

void *thread3(void *args)
{
  printf("Create Thread3\n");
  scanAp();
  return NULL;
}

typedef struct{
  u_int8_t dst[6];
  u_int8_t src[6];
  u_short len;
  u_char dsap[1];
  u_char ssap[1];
  u_char cf[1];
  u_char xidfmt[1];
  u_char llctype[1];
}TestPacket;

void make_testpacket(TestPacket *test)
{
  //char *tmp="ff:ff:ff:ff:ff:ff";
  u_char smac[6];
  u_char dmac[6];
  
  my_ether_aton_r(dev1MacAddr, smac);
  my_ether_aton_r(testmac, dmac);

  memcpy(test->dst, dmac, 6);
  memcpy(test->src, smac, 6);
  test->len=htons(0x0006);
  my_ether_aton_r("0x00", test->dsap);
  my_ether_aton_r("0x01", test->ssap);
  my_ether_aton_r("0xaf", test->cf);
  my_ether_aton_r("0x81", test->xidfmt);
  my_ether_aton_r("0x01", test->llctype);
}

void sendTestPacket()
{
  printf("Test Start\n");
  
  //char *dmac="ff:ff:ff:ff:ff:ff";
  u_char   send_buff[MAXSIZE];
  //u_char smac_addr[6];
  //u_char dmac_addr[6];

  //my_ether_aton_r(dev2MacAddr, smac_addr);
  //my_ether_aton_r(dmac, dmac_addr);
 
  make_testpacket((TestPacket *)send_buff);

  int len;
  len=sizeof(struct ether_header)+sizeof(MYPROTO);
  if(write(Device[0].soc, send_buff, len) < 0){
    perror("write");
  }
}

int main(int argc,char *argv[],char *envp[])
{
  getArpCache();
  pthread_t th1, th2, th3;

  // Initialize Physical Interface IP Address
  if(chgIfIp(NameDev3, inet_addr(dev3IpAddr))==0){
    printf("Change IP Address\n%s IP: %s\n", NameDev3, dev3IpAddr);
  }

  // Get Interface Infomation
  getIfMac(NameDev1, dev1MacAddr);
  getIfIp(NameDev1, dev1IpAddr);
  getIfMac(NameDev2, dev2MacAddr);
  getIfIp(NameDev2, dev2IpAddr);
  getIfMac(NameDev3, dev3MacAddr);
  //getIfIp(NameDev3, dev3IpAddr);

  // Init Socket
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
  if((Device[2].soc=InitRawSocket(NameDev3,1,0))==-1){
    DebugPrintf("InitRawSocket:error:%s\n",NameDev3);
    return(-1);
  }
  DebugPrintf("%s OK\n",NameDev3);

  DisableIpForward();

  signal(SIGINT,EndSignal);
  signal(SIGTERM,EndSignal);
  signal(SIGQUIT,EndSignal);

  signal(SIGPIPE,SIG_IGN);
  signal(SIGTTIN,SIG_IGN);
  signal(SIGTTOU,SIG_IGN);

  //-----
  sendTestPacket();
  return(0);
  //-----
  
  DebugPrintf("bridge start\n");
  int status;
  if ((status = pthread_create(&th1, NULL, thread1, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }
  if ((status = pthread_create(&th2, NULL, thread2, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }
  if ((status = pthread_create(&th3, NULL, thread3, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }
  DebugPrintf("bridge end\n");

  pthread_join(th1, NULL);
  pthread_join(th2, NULL);

  close(Device[0].soc);
  close(Device[1].soc);
  close(Device[2].soc);
  
  return(0);
}
