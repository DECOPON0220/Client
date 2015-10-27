#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <pthread.h>
//----- RewritePacket()
#include <netinet/tcp.h>
#include <netinet/udp.h>
//-----

#include "mydef.h"
#include "mystruct.h"
#include "myprotocol.h"
#include "ifutil.h"
#include "aputil.h"
#include "netutil.h"
#include "checksum.h"
#include "debug.h"



// --- Global Variable ---
const char *NameDev1="wlan0";
const char *NameDev2="wlan1";
const char *NameDev3="eth0";
const char *apEssId="test_ap";
const char *filename="myap.dat";

int DebugOut=OFF;
int EndFlag=OFF;
int StatusFlag=STA_DISCOVER;
int ClientMacFlag=OFF;
int ScanFlag=OFF;
int MainDev=WLAN1;
int SendFlag=ON;

char apMacAddr[SIZE_MAC];
char apIpAddr[SIZE_IP];
char cliMacAddr[SIZE_MAC];
char *cliIpAddr="192.168.100.11";
char dev1MacAddr[SIZE_MAC];
char dev2MacAddr[SIZE_MAC];
char dev3MacAddr[SIZE_MAC];
char dev1IpAddr[SIZE_IP];
char dev2IpAddr[SIZE_IP];
char dev3IpAddr[SIZE_IP];

DEVICE	Device[3];



int AnalyzePacket(int deviceNo, u_char *data, int size)
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
  if(ClientMacFlag==OFF){
    if(ntohs(eh->ether_type)==ETHERTYPE_IP){
      struct iphdr *iphdr;
      
      iphdr=(struct iphdr *)ptr;
      ptr+=sizeof(struct iphdr);
      lest-=sizeof(struct iphdr);
      if(strncmp(cliIpAddr, inet_ntoa(*(struct in_addr *)&iphdr->saddr), SIZE_IP)==0){
	my_ether_ntoa_r(eh->ether_shost, cliMacAddr, sizeof(cliMacAddr));	
	ClientMacFlag=ON;
        DebugPrintf("cliMacAddr: %s\n", cliMacAddr);
      }
    }
  }

  // Check My Protocol
  if(ntohs(eh->ether_type)==MYPROTOCOL){
    MYPROTO *myproto;
    myproto=(MYPROTO *)ptr;
    ptr+=sizeof(MYPROTO);
    lest-=sizeof(MYPROTO);

    switch(ntohs(myproto->type)){
    case   OFFER:;
      char offr_dMacAddr[18];
      char offr_sMacAddr[18];
      my_ether_ntoa_r(eh->ether_dhost, offr_dMacAddr, sizeof(offr_dMacAddr));
      my_ether_ntoa_r(eh->ether_shost, offr_sMacAddr, sizeof(offr_sMacAddr));
      
      if(strncmp(offr_dMacAddr, dev1MacAddr, sizeof(offr_dMacAddr))==0){
	strncpy(apMacAddr, offr_sMacAddr, SIZE_MAC);
	memcpy(dev1IpAddr, inet_ntoa(*(struct in_addr *)&myproto->ip_dst), SIZE_IP);
	memcpy(apIpAddr, inet_ntoa(*(struct in_addr *)&myproto->ip_src), SIZE_IP);
	if(chgIfIp(NameDev1, inet_addr(dev1IpAddr))==0){
	  DebugPrintf("Change IP Address\n%s IP: %s\n", NameDev1, dev1IpAddr);

	  printf("Send Approval Packet\n");
	  create_myprotocol(Device[MainDev].soc, dev1MacAddr, apMacAddr, dev1IpAddr, apIpAddr, APPROVAL);
	  StatusFlag=STA_WAIT;
	  
	  return(-1);
	}
      }
      break;
    default:
      break;
    }
  }



  /*
  if(StatusFlag==STA_DISCOVER) {
    // Check Offer Packet
    if(chkMyProtocol(data, apMacAddr, dev1MacAddr, apIpAddr, dev1IpAddr, OFFER, size)==-1){
      //StatusFlag=STA_APPROVAL;
      return(-1);
    }
  }
  */

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

int sendMyProtocol()
{
  int numMyAp;
  int maxIndex;

  while(EndFlag==OFF){
    if(ScanFlag==ON && SendFlag==ON){
      char *sip = "00H.00H.00H.00H";
      char *dip = "FF.FF.FF.FF";
      
      numMyAp=getNumMyAP(filename);
      INFOAP InfoMyAp[numMyAp];
      getMyApInfo(filename, numMyAp, InfoMyAp);
      int i;
      for(i=0;i<numMyAp;i++){
	DebugPrintf("infoMyAp[%d].MacAddr: %s\n", i, InfoMyAp[i].MacAddr);
	DebugPrintf("infoMyAp[%d].Quality: %d\n", i, InfoMyAp[i].Qual);
      }
      
      switch(StatusFlag){
      case   STA_DISCOVER:;
	printf("Send Discover Packet\n");
	
	maxIndex=getMaxQualIndex(InfoMyAp, numMyAp);
	DebugPrintf("maxIndex: %d\n", maxIndex);
	//memcpy(apMacAddr, InfoMyAp[maxIndex].MacAddr, SIZE_MAC);
	create_myprotocol(Device[MainDev].soc, dev1MacAddr, InfoMyAp[maxIndex].MacAddr, sip, dip, DISCOVER);
	usleep(10000 * 100);
	break;
      case   STA_APPROVAL:;
	DebugPrintf("Send Approval Pakcet\n");
	
	create_myprotocol(Device[MainDev].soc, dev1MacAddr, InfoMyAp[maxIndex].MacAddr, dev1IpAddr, apIpAddr, APPROVAL);
	StatusFlag=STA_WAIT;
	SendFlag=OFF;
      default:
	break;
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
  
  // WLAN1
  targets[0].fd=Device[0].soc;
  targets[0].events=POLLIN|POLLERR;
  // WLAN2
  targets[1].fd=Device[1].soc;
  targets[1].events=POLLIN|POLLERR;
  // ETH1
  targets[2].fd=Device[2].soc;
  targets[2].events=POLLIN|POLLERR;

  while(EndFlag==OFF){
    if(ScanFlag==ON){
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
		/*
		if(i==0){
		  if((size=write(Device[2].soc,buf,size))<=0){
		    //perror("write");
		  }
		}else if(i==2){
		  if((size=write(Device[0].soc,buf,size))<=0){
		    //perror("write");
		  }
		}
		*/
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

int scanAp()
{
  FILE       *result, *fp;
  const char *tmpfile = "ap.dat";
  const char *tmpcmd = "iwlist %s scan | egrep 'Cell |ESSID|Quality'";
  char       cmdline[64];
  int        numAP;

  while(EndFlag==OFF){
    DebugPrintf("Start Scan\n");
    
    // Make Command
    if(MainDev==WLAN1){
      sprintf(cmdline, tmpcmd, NameDev2);
    }else if(MainDev==WLAN2){
      sprintf(cmdline, tmpcmd, NameDev1);
    }

    if ((result=popen(cmdline, "r")) == NULL){
      perror ("Command error");
    }

    char buf[256];

    // Overwride AP data in 'ap.dat'
    if ((fp=fopen(tmpfile, "w")) == NULL){
      perror ("File Open error");
    }
    while(!feof(result)){
      fgets(buf, sizeof(buf), result);
      fputs(buf, fp);
    }
    fclose(fp);
    (void) pclose(result);
    
    // Get the information of AP
    if((numAP=getNumAP(tmpfile))>0){
      INFOAP tmpInfoAp[numAP];
      getAPInfo(tmpfile, numAP, tmpInfoAp);
      
      // Write My Access Point
      if ((fp=fopen(filename, "w")) == NULL){
	perror ("File Open error");
      }
      fclose(fp);
      if ((fp=fopen(filename, "a")) == NULL){
	perror ("File Open error");
      }
      int i;
      for(i=0;i<numAP;i++){
	if(strcmp(tmpInfoAp[i].ESSID, apEssId)==0){	
	fprintf(fp, "Address : %s\n", tmpInfoAp[i].MacAddr);
	fprintf(fp, "Quality : %d\n", tmpInfoAp[i].Qual);
	}
      }
      fclose(fp);

      // Success Get My AP
      if(getNumMyAP(filename)>0){
	ScanFlag=ON;
	DebugPrintf("Finish Scan\n");
      }else{
	ScanFlag=OFF;
      }
    }else{
      ScanFlag=OFF;
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
  EndFlag=ON;
}

void *thread1(void *args)
{
  DebugPrintf("Create Thread1\n");
  Bridge();
  return NULL;
}

void *thread2(void *args)
{
  DebugPrintf("Create Thread2\n");
  sendMyProtocol();
  return NULL;
}

void *thread3(void *args)
{
  DebugPrintf("Create Thread3\n");
  scanAp();
  return NULL;
}

int main(int argc, char *argv[], char *envp[])
{
  pthread_t th1, th2, th3;

  getArpCache();

  // Initialize Physical Interface IP Address
  if(chgIfIp(NameDev3, inet_addr(dev3IpAddr))==0){
    DebugPrintf("Change IP Address\n%s IP: %s\n", NameDev3, dev3IpAddr);
  }

  // Get Interface Infomation
  getIfMac(NameDev1, dev1MacAddr);
  // getIfIp(NameDev1, dev1IpAddr);
  getIfMac(NameDev2, dev2MacAddr);
  //getIfIp(NameDev2, dev2IpAddr);
  getIfMac(NameDev3, dev3MacAddr);
  getIfIp(NameDev3, dev3IpAddr);

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
  
  DebugPrintf("Thread Start\n");
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

  pthread_join(th1, NULL);
  pthread_join(th2, NULL);
  pthread_join(th3, NULL);

  close(Device[0].soc);
  close(Device[1].soc);
  close(Device[2].soc);
  
  return(0);
}
