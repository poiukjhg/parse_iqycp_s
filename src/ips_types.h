#ifndef IPS_TYPES_H_
#define IPS_TYPES_H_
#include "my_queue.h"

#ifndef Local
#define Local static
#endif

#define RES_ERROR -1
#define RES_OK 0
#define my_true 1
#define my_false 0
#define REGEX_HIT 0
#define REGEX_MISS 1
#define IP_LEN 20
#define DEFAULT_REMAINNING_TIME 300
#define MAX_PARSE_CLIENT 100
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) \
((unsigned char *)&addr)[0],  ((unsigned char *)&addr)[1],  ((unsigned char *)&addr)[2],  ((unsigned char *)&addr)[3]

#define MAC_FMT "%02x%02x%02x%02x%02x%02x"
#define MACQUAD(addr) \
((unsigned char *)&addr)[0],  ((unsigned char *)&addr)[1],  ((unsigned char *)&addr)[2],  ((unsigned char *)&addr)[3], ((unsigned char *)&addr)[4], ((unsigned char *)&addr)[5]
#define SNAP_LEN 1518 
#define URL_LEN 1024
typedef unsigned int	my_uint32;
typedef struct parse_url_node_s parse_url_node_t;

struct parse_url_node_s {
	char url[URL_LEN];
	char checked_client[IP_LEN*MAX_PARSE_CLIENT];
	int checked_client_num;
	my_uint32 remaining_time;
	my_queue_t parse_queue;
 };

void *p_lock;
parse_url_node_t p_url_q;
#endif
