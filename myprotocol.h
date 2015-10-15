#define DISCOVER 0x1001
#define OFFER    0x1002
#define APPROVAL  0x1003

struct myprotocol {
  u_int32_t ip_src;
  u_int32_t ip_dst;
  u_short type;
};
