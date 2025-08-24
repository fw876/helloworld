#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>

#ifndef TCP_H_DEFINED
#define TCP_H_DEFINED
int lookup(char *host, char *portnr, struct addrinfo **res);
int connect_to(struct addrinfo *addr, struct timeval *rtt, int timeout);
#endif				/* TCP_H_DEFINED */
