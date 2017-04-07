#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>     
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>         
#include <sys/socket.h>
#include <assert.h>
#include <string.h>
#include <ev.h>
#include "mylogs.h"
#include "ips_types.h"
#include "server_handler.h"
#include "mylock.h"

 
//  char ipaddr[PEER_IP_LENGTH];
//  char string_addr[PEER_STRING_LENGTH];
char default_resp[] = "HAS_CHECKED\n\r";
Local int getpeer_information(int fd, char* ipaddr, int len)
 {
	struct sockaddr_in name;
	size_t namelen = sizeof(name);

	assert(fd >= 0);
	assert(ipaddr != NULL);
	
	memset(ipaddr, '\0', IP_LEN);
	if (getpeername(fd, (struct sockaddr *)&name, (socklen_t *)&namelen) != 0) {
		log_output("get peer name error\n\r");
	 	return RES_ERROR;
	} 
	else {
		/*
		strncpy(ipaddr,
			inet_ntoa(*(struct in_addr *)&name.sin_addr.s_addr),
		 	IP_LEN);
		 	*/
		inet_ntop(AF_INET, &name.sin_addr, ipaddr, len);
		log_output("peer ip = %s \n\r", ipaddr);		
	}
	return RES_OK;
  }
Local  char *relloc_buf(char* old_buf, char* new_str, int old_len, int new_len, char end_flag)
{
	int len = old_len+new_len+1;
	char *new_buf = old_buf;
	assert(new_str !=NULL);
	assert(new_len  >0);	
	if (new_buf != NULL && len < BUFFER_SIZE){
		new_buf = old_buf;
		memcpy(new_buf+old_len, new_str, new_len);
		new_buf[old_len+new_len] = end_flag;
	}
	else {
		new_buf = (char *)malloc(old_len+new_len+1);
		if (new_buf == NULL){
			free(old_buf);
			return NULL;
		}
		memset(new_buf, 0, old_len+new_len+1);
		memcpy(new_buf, old_buf, old_len);
		memcpy(new_buf+old_len, new_str, new_len);
		free(old_buf);
		old_buf = NULL;		
	}
	new_buf[old_len+new_len] = end_flag;	
	return new_buf;
}

Local  char *get_response(int accept_fd)
{
	assert(accept_fd>0);
	char *peer_ip = (char *)malloc(IP_LEN);
	my_queue_t *cur_q_node;
	parse_url_node_t *cur_node;
	int index = 0;
	char *checked;
	Local  int has_checked = my_false;
	char *url = NULL;
	int checked_client_num;
	memset(peer_ip, 0, IP_LEN);
	if(getpeer_information(accept_fd, peer_ip, IP_LEN) == RES_ERROR){
		free(peer_ip);
		return NULL;
	}
	log_output("peer ip = %s \n\r", peer_ip);	
	my_queue_foreach(cur_q_node, &p_url_q.parse_queue){	
		has_checked = my_false;
		log_output("has_checked = %s\n\r", has_checked == my_false?"FALSE":"TRUE");
		cur_node = my_queue_data(cur_q_node, parse_url_node_t, parse_queue);
		checked = cur_node->checked_client;
		checked_client_num = cur_node->checked_client_num;
		log_output("start to check ip index = %d, ip =%s, len = %d\n\r",index, checked, (int)strlen(checked));
		for(index = 0; index<checked_client_num; index++){
			log_output("check accept ip = %s, len = %d\n\r", peer_ip, (int)strlen(peer_ip));
			if (strncmp(checked, peer_ip, IP_LEN) == 0){	
				log_output("%s == %s, eaque\n\r", checked, peer_ip);
				has_checked = my_true;
				url = NULL;
				log_output("has_checked = %s\n\r", has_checked == my_false?"FALSE":"TRUE");
				break;
			}
			checked+=IP_LEN;			
		}
		log_output("has_checked = %s\n\r", has_checked == my_false?"FALSE":"TRUE");
		if(has_checked == my_false){
			log_output("add ip = %s into list \n\r", peer_ip);
			memcpy(cur_node->checked_client+IP_LEN*cur_node->checked_client_num, peer_ip, IP_LEN);
			cur_node->checked_client_num++;
			url  =cur_node->url;
			log_output("url = %s \n\r", url);
			break;
		}
			
	}
	free(peer_ip);
	if(!url)
		url = default_resp;
	return url;
}
Local int init_listen(int port)
{
	int listen_fd = -1;
	struct sockaddr_in sin; 
	int flags;
	assert(port>0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = 0;
	sin.sin_port = htons(port);
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);	
	if ((flags = fcntl(listen_fd, F_GETFL, NULL)) < 0) {
		handle_error("fcntl get");
		exit(-1);
	}
	if (!(flags & O_NONBLOCK)) {
		if (fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
			handle_error("fcntl set");
			exit(-1);
		}
	}                      
	if(bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin))<0){
		handle_error("bind port");
		exit(-1);
	}
	if( listen(listen_fd, 16) == -1){  
		handle_error("listen");
		exit(-1);
	} 	
	return listen_fd;
}

Local struct ev_loop *server_init()
{
	struct ev_loop *base;	
	base = EV_DEFAULT;
	if (base == NULL)  {
		handle_error("ev base init");
		return NULL;   	
	}	
	return base;
}	

Local void server_start(struct ev_loop *base)
{
	int  res;
	log_output("loop start %d\n\r", (int)getpid());
	if (base != NULL){
		res = ev_run (base, 0);
		log_output("loop back %d, res = %d\n\r", (int)getpid(), res);
	}
}

Local char check_request(char* str)
{
//TODO
	return 1;
}

Local void my_read_cb(EV_P, ev_io *w, int revents)
{  
	char *read_buf = NULL;
	char *tmp_read_buf = (char *)malloc(BUFFER_SIZE);
	char *write_buf = NULL;
	char *tmp_write_buf = NULL;
	int read_len = 0;
	int tmp_read_len = 0;
	ssize_t write_len = 0;
	ssize_t tmp_write_len = 0;	
	
	if (tmp_read_buf == NULL)
		handle_error("malloc");
	read_buf = (char *)malloc(BUFFER_SIZE);
	if (read_buf == NULL)
		handle_error("read_buf malloc");
	memset(read_buf, '0', BUFFER_SIZE);
	while(my_true){
		memset(tmp_read_buf, '0', BUFFER_SIZE);
		tmp_read_len = read(w->fd, tmp_read_buf, BUFFER_SIZE);
		if (tmp_read_len < 0 ){
			free(tmp_read_buf);
			tmp_read_buf = NULL;
			if(errno == EAGAIN || errno == EWOULDBLOCK){
				log_output("read looop EWOULDBLOCK or EAGAIN\n\r");								
				break;
			}
		       if (errno == EINTR)
			      continue;
			else{				
				handle_error_without_exit("read");
				goto fd_fail;
			}
		}
		else if(tmp_read_len == 0){
			free(tmp_read_buf);
			tmp_read_buf = NULL;
			break;
		}
		else{
			read_buf = relloc_buf(read_buf, tmp_read_buf, read_len, tmp_read_len, '|');
			read_len = read_len+tmp_read_len;
		}
	}	
	if(check_request(read_buf) == 1){
		write_buf = get_response(w->fd);
		log_output("response buf = %s \n\r", write_buf);
		if (write_buf == NULL){
			goto fd_fail;

		}
		write_len = strlen(write_buf);
		tmp_write_buf = write_buf;
		while(my_true){
			tmp_write_len = write(w->fd, tmp_write_buf, write_len);
			log_output("send len = %d \n\r", (int)tmp_write_len);
			if(tmp_write_len <0){
				if(errno == EAGAIN || errno ==EWOULDBLOCK)
					goto fd_fail;
				if (errno == EINTR)
		      			continue;
				else
					handle_error("write");
			}
			else if(write_len == 0){				
				break;
			}
			else{
				write_len = write_len -tmp_write_len;
				tmp_write_buf = tmp_write_buf +tmp_write_len;
			}
		}						
	}	
fd_fail:
	if(tmp_read_buf){
		free(tmp_read_buf);	
		tmp_read_buf = NULL;
	}
	if(read_buf){
		free(read_buf);
		read_buf = NULL;
	}
	close(w->fd);
	ev_io_stop (EV_A, w);
	free(w);
	return;
}

Local void my_accept_cb(EV_P, ev_io *w, int revents)
{
	int accept_fd;
	ev_io *r_ev = (ev_io *)malloc(sizeof(ev_io));
	if (r_ev == NULL){
		handle_error("ev malloc\n\r");
	}
	struct sockaddr_storage ss;   	
	socklen_t slen = sizeof(ss);  
	while (1) {
		accept_fd = accept(w->fd, (struct sockaddr*)&ss, &slen); 
		if (accept_fd == -1) {
			if (errno == EINTR){
				log_output("accept intr\n\r");
				continue;
			}
			else{
				log_output("accept error\n\r");
				break;
			}
		}
		else{
			log_output("accept %d  ok\n\r", accept_fd);
			break;
		}		
	}	
	if (accept_fd < 0) {  		 
		if (errno == EAGAIN || errno == EWOULDBLOCK){
			return;
		}
		else
			handle_error("accept"); 
	}  
	else  {  
		log_output("accept fd %d, listen fd %d\n\r", accept_fd, w->fd);
		setNonblock(accept_fd);
		ev_io_init (r_ev, my_read_cb,  accept_fd, EV_READ);
		ev_io_start (EV_A, r_ev);		
	}  	
}

Local void my_timeout_cb (EV_P, ev_timer *w, int revents)
{
	my_queue_t *cur_q_node;
	parse_url_node_t *cur_node;
	parse_url_node_t *last_del_node = NULL;	
	my_uint32 remaining_time = 1;
	ev_timer *mytimer = w->data;
	my_uint32 pass_time = p_url_q.remaining_time;
	log_output("timeout cb addr = %p\n\r", mytimer);
	if ( !my_queue_empty(&p_url_q.parse_queue) ){	
		my_queue_foreach(cur_q_node, &p_url_q.parse_queue){	
			if(last_del_node){
				if(my_lock_trylock(p_lock) == RES_OK){
					log_output("remove node %s\n\r", last_del_node->url);
					my_queue_remove(&last_del_node->parse_queue);
					free(last_del_node);
					my_lock_tryunlock(p_lock);
					log_output("remove ok\n\r");						
				}
				last_del_node = NULL;
			}	
			cur_node = my_queue_data(cur_q_node, parse_url_node_t, parse_queue);				
			if (cur_node->remaining_time< pass_time){
				last_del_node = cur_node;
			}
			else{
				cur_node->remaining_time -= pass_time;
				log_output("node url = %s remaining_time = %d\n\r", cur_node->url, cur_node->remaining_time);
			}
		}	
	}
	if(last_del_node){
		if(my_lock_trylock(p_lock) == RES_OK){
			log_output("remove node %s\n\r", last_del_node->url);
			my_queue_remove(&last_del_node->parse_queue);
			free(last_del_node);
			my_lock_tryunlock(p_lock);
			log_output("remove ok\n\r");						
		}
		last_del_node = NULL;
	}
	if ( !my_queue_empty(&p_url_q.parse_queue) ){
		log_output("start reset next remainning time \n\r");
		cur_q_node = my_queue_head(&p_url_q.parse_queue);	
		cur_node = my_queue_data(cur_q_node, parse_url_node_t, parse_queue);
		remaining_time = cur_node->remaining_time+1;
		log_output("reset next remainning time %d\n\r", remaining_time);
	}
	p_url_q.remaining_time = remaining_time;
	log_output("remainning time %d\n\r", remaining_time);
	ev_timer_stop(loop, mytimer); 
	ev_timer_set(mytimer, remaining_time, 0.);
	ev_timer_start (loop, mytimer); 	
}
Local void my_try_to_timer(EV_P)
{
	my_queue_t *cur_q_node;
	parse_url_node_t *cur_node;
	my_uint32 remaining_time = 1;
	if ( !my_queue_empty(&p_url_q.parse_queue) ){		
		cur_q_node = my_queue_head(&p_url_q.parse_queue);	
		cur_node = my_queue_data(cur_q_node, parse_url_node_t, parse_queue);
		remaining_time = cur_node->remaining_time;
	}
	p_url_q.remaining_time = remaining_time;
	ev_timer *mytimer =(ev_timer *) malloc(sizeof(ev_timer));
	ev_timer_init (mytimer, my_timeout_cb, remaining_time, 0.);
	mytimer->data = mytimer;
	log_output("my_timer addr = %p", mytimer);
	ev_timer_start (EV_A, mytimer);
}

Local void my_try_to_listen(EV_P, int listen_fd)
{
	ev_io *ev;
	ev = (ev_io *)malloc(sizeof(ev_io));
	if (ev == NULL){
		handle_error("ev malloc\n\r");
	}	
	ev_io_init (ev, my_accept_cb,  listen_fd, EV_READ);
	ev_io_start (EV_A, ev);
	log_output("listen fd %d\n\r", listen_fd);
}

void *server_handler(void *arg){
	log_output("server_handler start \n\r");	
	struct ev_loop * base = server_init();
	int listen_fd = init_listen(BIND_PORT);
	assert(listen_fd >0);
	log_output("linsten %d\n\r", BIND_PORT);		
	my_try_to_listen(base, listen_fd);
	my_try_to_timer(base);
	server_start(base);
	return NULL;
}
