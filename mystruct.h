typedef struct {
  int	soc;
}DEVICE;
DEVICE	Device[3];

typedef struct {
  char MacAddr[SIZE_MAC];
  int Qual;
  char ESSID[64];
}INFOAP;

typedef struct{
  u_int32_t ip_src;
  u_int32_t ip_dst;
  u_short   type;
}MYPROTO;
