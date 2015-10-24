#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "mydef.h"
#include "mystruct.h"
#include "netutil.h"



void make_ethernet(struct ether_header *eth,unsigned char *ether_dhost,
		   unsigned char *ether_shost,u_int16_t ether_type)
{
  memcpy(eth->ether_dhost,ether_dhost,6);
  memcpy(eth->ether_shost,ether_shost,6);
  eth->ether_type=htons(ether_type);
}

void make_mydhcp(MYPROTO *myproto,char *sip,char *dip,u_short type)
{
  myproto->ip_src=inet_addr(sip);
  myproto->ip_dst=inet_addr(dip);
  myproto->type=htons(type);
}

void create_myprotocol(int soc,char *smac,char *dmac,char *sip,char *dip,u_short type)
{
  char   *sp;
  char   send_buff[MAXSIZE];
  u_char smac_addr[6];
  u_char dmac_addr[6];

  sp = send_buff + sizeof(struct ether_header);

  my_ether_aton_r(smac, smac_addr);
  my_ether_aton_r(dmac, dmac_addr);
  
  make_mydhcp((MYPROTO *) sp, sip, dip, type);
  make_ethernet((struct ether_header *) send_buff, dmac_addr, smac_addr, type);

  int len;
  len = sizeof(struct ether_header) + sizeof(MYPROTO);
  if (write(soc, send_buff, len) < 0) {
    perror("write");
  }
}
