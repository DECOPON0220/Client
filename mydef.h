#define MAXSIZE  8192
#define SIZE_MAC 18
#define SIZE_IP  15
#define DISCOVER 0x1001
#define OFFER    0x1002
#define APPROVAL 0x1003

// ARP CACHE
#define xstr(s) str(s)
#define str(s) #s
#define ARP_CACHE       "/proc/net/arp"
#define ARP_STRING_LEN  1023
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)
#define ARP_LINE_FORMAT "%" xstr(ARP_STRING_LEN) "s %*s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s"
