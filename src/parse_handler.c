#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>    
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>        //Provides declarations for tcp header 
#include <netinet/ip.h>     //Provides declarations for ip header 
#include <ctype.h>
#include <assert.h>
#include "mylogs.h"
#include "ips_types.h"
#include "parse_handler.h"
#include "reg_handler.h"
#include "mylock.h"

const char HTTP_GET_STR[] = "GET"; 

/*
struct ethhdr {
unsigned char h_dest[ETH_ALEN];
unsigned char h_source[ETH_ALEN];
__be16 h_proto;
} __attribute__((packed));

struct ether_header
{
u_int8_t ether_dhost[ETH_ALEN];      // destination eth addr 
u_int8_t ether_shost[ETH_ALEN];      // source ether addr    
u_int16_t ether_type;                 // packet type ID field 
} __attribute__ ((__packed__));

***********************IP的结构***********************************
struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
};

***********************TCP的结构****************************
struct tcphdr
{
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
# else
#   error "Adjust your <bits/endian.h> defines"
# endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};
***********************UDP的结构*****************************
struct udphdr
{
u_int16_t source;
u_int16_t dest;
u_int16_t len;
u_int16_t check;
};
*/

int check_url(char *payload, reg_result_t *reg_res, int len)
{
	//"/videos/v0/20170320/50/66/3d3a0aa4a5bf6169135ac19f2a171e6f.f4v?key=0b1d4e344537530d16035caf48eb5b512"
	assert(payload);
	char *head = payload;
	log_output("regres check url = %s \n\r", head);
	reg_handler(reg_res, head);
	if(reg_res->result == REGEX_HIT){
		log_output("regres hit url = %s \n\r", head);
		reg_res->result = REGEX_MISS;	
		return RES_OK;
	}
	reg_res->result = REGEX_MISS;
	return RES_ERROR;
}

void insert_url_into_list(char *payload, int len)
{
	assert(payload);
	assert(len >0);
	char *cur = NULL;
	char *head = payload;
	char *url_start = NULL;
	char *url_end = NULL;
	char *host_start = NULL;
	char *host_end = NULL;	
	parse_url_node_t *url_node;
	int host_len = 0;
	const char * http_head = "http://";
		
	url_start = strstr(head, "/");
	if ( !url_start){
		log_output("url_start not hit\n\r");
		return;
	}
	url_end = strstr(url_start, "&");
	if ( !url_end)
		url_end = strstr(url_start, " ");	
	if ( !url_end){
		log_output("url_end not hit\n\r");
		return;
	}
	host_start = strstr(url_end, "ost:");
	if ( !host_start){
		log_output("host_start not hit\n\r");
		return;
	}
	while(*host_start == ' ') 
		host_start++;
	host_start+=5;
	host_end = strstr(host_start, "\n");
	if ( !host_end)
	{
		log_output("host_end not hit\n\r");
		return;
	}
	host_end-=1;
	assert(host_end>host_start);
	host_len = host_end - host_start;
	url_node = (parse_url_node_t *)malloc(sizeof(parse_url_node_t));
	if (url_node == NULL){
		handle_error_without_exit("url malloc");
		return;
	}
	memset(url_node, 0, sizeof(parse_url_node_t));
	cur = url_node->url;
	memcpy(cur, http_head, strlen(http_head));
	cur+=strlen(http_head);
	memcpy(cur, host_start, host_len);
	cur+=host_len;
	memcpy(cur, url_start, url_end-url_start);
	cur+=url_end-url_start;
	memcpy(cur, "\n\r", 2);
	url_node->remaining_time = DEFAULT_REMAINNING_TIME;	
	while(my_lock_trylock(p_lock) == RES_ERROR);
	my_queue_insert_tail(&p_url_q.parse_queue, &url_node->parse_queue);
	my_lock_tryunlock(p_lock);
	log_output("insert into queue, node = %s\n\r", url_node->url);
}
void output_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
#ifdef DEBUG
	const struct ethhdr *ethernet;
	const struct iphdr *iph;
	const struct tcphdr *tcph; 
	int size_ethernet = sizeof(struct ethhdr);          
	int i;

	ethernet = (struct ethhdr*)(packet);
	iph = ( struct iphdr * ) ( packet   + size_ethernet) ; 
	tcph = ( struct tcphdr * ) ( packet +  iph -> ihl*4 + size_ethernet) ; 
	
	log_output("start out Payload:\n\r");
	for (i = 0; i < pkthdr->len; i++) { 
		if(i%8 == 0)
			printf("\n\r");                  
		if(packet[i] == 0)
			printf("00");
		else                     
			printf("%02x", packet[i]);                    
	}    
	      
	printf("\n\r");  
	log_output("Received Packet Size: %d, %d\n\r", pkthdr->len,  pkthdr->caplen);  
	log_output("eth src addr: 0x"MAC_FMT"\n\r", MACQUAD(ethernet->h_source));
	log_output("eth dst addr: 0x"MAC_FMT"\n\r", MACQUAD(ethernet->h_dest));
	log_output("des ip " NIPQUAD_FMT"\n\r", NIPQUAD(iph->daddr));
	log_output("src ip " NIPQUAD_FMT"\n\r", NIPQUAD(iph->saddr));  
	log_output("ip len %d \n\r", ntohs(iph->ihl));
	log_output("src port:%d \n\r", ntohs(tcph->source));
	log_output("dst port:%d \n\r", ntohs(tcph->dest));
	log_output("seq %u, ack:%u, flags:0x%02x\n\r", ntohl(tcph->seq), ntohl(tcph->ack_seq), (int)*(char *)(tcph+4+offsetof( struct tcphdr, ack_seq)));
	log_output("http payload: ");    
	for(i = (size_ethernet + iph->ihl*4 + tcph->doff*4); i < pkthdr->len; i++){
	    if (isprint(packet[i]))
	        printf("%c", packet[i]);
	    else
	        printf("%2x", packet[i]);           
	} 
	printf("\n\r");  
#endif
}
void my_pcap_callback(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int count = 0;
	struct iphdr *iph;
	struct tcphdr *tcph;
	char *payload; 
	int size_ethernet = sizeof ( struct ethhdr );
	int size_ip = -1;
	int size_tcp = -1;    
	int pay_load_len;
	reg_result_t *reg_res = (reg_result_t *)user_data;
	iph = ( struct iphdr * ) ( packet   + size_ethernet) ; 
	tcph = ( struct tcphdr * ) ( packet +  iph -> ihl*4 + size_ethernet) ;
	size_ip = iph->ihl*4;
	size_tcp = tcph->doff*4;
	
	count++;  
	payload = (char *)(packet + size_ethernet +  size_ip + size_tcp);
	pay_load_len = pkthdr->len-size_ethernet - size_ip - size_tcp;
	if (pay_load_len == 0)
		return;
	if (strncasecmp(payload, HTTP_GET_STR, 3) == 0){			
		if (check_url(payload, reg_res, pay_load_len) == RES_OK){
			//output_packet(pkthdr, packet);
			insert_url_into_list(payload, pay_load_len);
		}
	}        
	 
}

void packet_filter()
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fp;     
	bpf_u_int32 maskp;         
	bpf_u_int32 netp;  
	char res = RES_ERROR;
	const char *filter_str = "tcp dst port 80";
	char *reg_str = "(g|G)(e|E)(t|T)\\s+/videos/v0/[0-9]{8}/[^/]{2}/[^/]{2}/\\w+.f4v\\?key=[^&|\\s]+";
	reg_result_t * reg_res = NULL;
	log_output("start packet_filter\n\r");  
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){ 
		handle_error("pcap lookup");
	}
	log_output("dev = %s\n\r", dev);    
	pcap_lookupnet(dev, &netp, &maskp, errbuf);   
	log_output("start to open live \n\r");
	descr = pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
	if(descr == NULL){ 
		handle_error("pcap_open_live");
	}
	log_output("start to compile \n\r");
	if(pcap_compile(descr, &fp, filter_str, 0, netp) == -1){ 
	    pcap_perror(descr, "Error calling pcap_compile");
	    pcap_close(descr);
	    handle_error("pcap_compile");
	}
	log_output("start to install filter str: %s\n\r", filter_str);
	if(pcap_setfilter(descr,&fp) == -1){
	    pcap_close(descr);
	    handle_error("Error setting filter"); 
	} 
	log_output("start to init reg\n\r");
	reg_res = reg_init(reg_str);
	if (reg_res == NULL){
		handle_error("reg init"); 
	}
	log_output("start pcap_loop\n\r");     
	res = pcap_loop(descr, 0, my_pcap_callback, (u_char *)reg_res);
	pcap_close(descr);
	log_output("pcap res = %d\n\r", res);
	reg_destroy(reg_res);
}
void* parse_handler(void *arg)
{
	log_output("parse_handler start \n\r");
	packet_filter();
	return NULL;
}