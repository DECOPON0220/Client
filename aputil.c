#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include "mydef.h"
#include "mystruct.h"



int getNumAP(const char* file)
{
  FILE *fp;
  char buf[256];
  int  numLine;
  int  numAP;

  numLine=0;
  if((fp=fopen(file,"r"))==NULL){
    perror("FILE Open error");
  }
  while(fgets(buf,sizeof(buf),fp)!=NULL){
    numLine++;
  }
  
  numAP=((numLine-1)/ITEM_AP);
  
  fclose(fp);
  return numAP;
}

INFOAP *getAPInfo(const char* file,int numAP,INFOAP *tmpAP)
{
  FILE       *fp;
  char       buf[256];
  const char *Addr = "          Cell";
  const char *Qual = "                    Quality";
  const char *Ssid = "                    ESSID";
  const int  cmpAddr = 13;
  const int  cmpQual = 26;
  const int  cmpSsid = 24;
  int        plAddr, plQual, plSsid;
  int        nowAP, tmpNum;

  // Get the information of AP
  fp=fopen(file,"r");
  nowAP=0;
  while(fgets(buf,sizeof(buf),fp)!=NULL && nowAP<numAP){
    tmpNum = 0;
    // Get Address 
    if(strncmp(buf,Addr,cmpAddr)==0){
      plAddr=29;
      while(buf[plAddr]!='\n') {
	tmpAP[nowAP].MacAddr[tmpNum]=buf[plAddr];
	tmpNum++;
	plAddr++;
      }
      tmpAP[nowAP].MacAddr[tmpNum]='\0';
    }
    // Get Quality - 49
    if(strncmp(buf,Qual,cmpQual)==0) {
      char tmpChar[2];
      plQual=49;

      tmpChar[tmpNum]=buf[plQual];
      tmpNum++;
      plQual++;

      if(buf[plQual]==' '){
        tmpChar[tmpNum]='\0';
      }else{
	tmpChar[tmpNum]=buf[plQual];
      }
      tmpAP[nowAP].Qual=atoi(tmpChar);
    }
    // Get Quality - 27
    if(strncmp(buf,Ssid,cmpSsid)==0) {
      plSsid=27;
      while(buf[plSsid]!='\"'){
	tmpAP[nowAP].ESSID[tmpNum]=buf[plSsid];
	tmpNum++;
	plSsid++;
      }
      tmpAP[nowAP].ESSID[tmpNum]='\0';

      nowAP++;
    }
  }

  fclose(fp);
  return tmpAP;
}


int getNumMyAP(const char* file)
{
  FILE *fp;
  char buf[256];
  int  numLine;    // Line number of 'ap.dat'
  int  numAP;

  numLine=0;
  // Get the lines of 'ap.dat'
  if((fp=fopen(file,"r"))==NULL){
    perror("FILE Open error");
  }
  while(fgets(buf,sizeof(buf),fp)!=NULL){
    numLine++;
  }
  
  numAP = numLine / ITEM_MYAP;

  fclose(fp);
  return numAP;
}

INFOAP *getMyApInfo(const char* file,int numAP,INFOAP *tmpAP)
{
  FILE       *fp;
  char       buf[256];
  const char *Addr = "Address : ";
  const char *Qual = "Quality : ";
  const int  cmpAddr = 10;
  const int  cmpQual = 10;
  int        plAddr, plQual;
  int        nowAP, tmpNum;
  
  // Get the information of AP
  fp=fopen(file,"r");
  nowAP = 0;
  while(fgets(buf,sizeof(buf),fp)!=NULL && nowAP<numAP){
    tmpNum=0;
    // Get Address 10
    if (strncmp(buf,Addr,cmpAddr)==0){
      plAddr=10;
      while(buf[plAddr]!='\n'){
	tmpAP[nowAP].MacAddr[tmpNum]=buf[plAddr];
	tmpNum++;
	plAddr++;
      }
      tmpAP[nowAP].MacAddr[tmpNum]='\0';    // final char
    }
    // Get Quality - 10
    if(strncmp(buf,Qual,cmpQual)==0){
      char tmpChar[2];
      plQual=10;

      tmpChar[tmpNum]=buf[plQual];
      tmpNum++;
      plQual++;
      
      if(buf[plQual]==' '){
	tmpChar[tmpNum]='\0';
      }else{
	tmpChar[tmpNum]=buf[plQual];
      }
      tmpAP[nowAP].Qual=atoi(tmpChar);

      nowAP++;
    }
  }

  fclose(fp);
  return tmpAP;
}

int getMaxQualIndex(INFOAP *myap, int numMyAp)
{
  int i;
  int maxIndex;
  int maxQual;

  maxQual=myap[0].Qual;
  maxIndex=0;
  
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
