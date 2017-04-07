#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>     
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include "mylogs.h"
#include "ips_types.h"
#include "server_handler.h"
#include "parse_handler.h"
#include "mylock.h"

int main()
{
	int err;
	pthread_t pid[2];
	p_lock = NULL;
	my_lock_init(&p_lock);	
	memset(&p_url_q, 0, sizeof(parse_url_node_t));
	my_queue_init(&p_url_q.parse_queue);
	log_output("iparse start \n\r");		
	err = pthread_create(&pid[0], NULL, server_handler, NULL); 
	if ( err != 0 ) 
	{ 
	    handle_error("server pthread create");
	} 	
	err = pthread_create(&pid[1], NULL, parse_handler, NULL); 
	if ( err != 0 ) 
	{ 
	    handle_error("parse pthread create");
	} 	
	pthread_join (pid[0], NULL);
	pthread_join (pid[1], NULL);
	return 0;
}

