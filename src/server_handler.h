#ifndef SERVER_HANDLER_H_
#define SERVER_HANDLER_H_

#define BUFFER_SIZE 1024
#define BIND_PORT 8888
#define setNonblock(fd) do{ \
	int flags = fcntl(fd, F_GETFL, 0); \
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);\
}while(0)

void* server_handler(void *arg);
#endif