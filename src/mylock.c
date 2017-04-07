#include <stdlib.h>
#include <sys/stat.h>     
#include <unistd.h>     
#include "ips_types.h"
#include "mylogs.h"
#include "mylock.h"

int my_lock_init(void ** lock)
{
	pthread_mutex_t* mymutex = NULL;
	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
   	pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);   	
	*lock = (void *)malloc(sizeof(pthread_mutex_t));
	mymutex = (pthread_mutex_t *)(*lock);
	if (mymutex == NULL){
		handle_error("mmap");
		return RES_ERROR;
	}
	pthread_mutex_init(mymutex, &mutexattr);
	return RES_OK;
}

int my_lock_trylock(void* lock)
{
	int res = RES_OK;
	pthread_mutex_t* mymutex = (pthread_mutex_t*)lock;
	if (mymutex != NULL){		
		if((res = pthread_mutex_trylock(mymutex) ) != RES_OK)
			return RES_ERROR;
		else return RES_OK;
	}
	else 
		return RES_ERROR;		
}
int my_lock_tryunlock(void* lock)
{
	int res = RES_OK;
	pthread_mutex_t* mymutex = (pthread_mutex_t*)lock;
	if (mymutex != NULL){		
		if((res = pthread_mutex_unlock(mymutex) ) != RES_OK)
			return RES_ERROR;
		else return RES_OK;
	}
	else return RES_ERROR;
}

void my_lock_destroy(void* lock)
{
	pthread_mutex_t* mymutex = (pthread_mutex_t*)lock;
	munmap(mymutex, sizeof(pthread_mutex_t)); 
}


