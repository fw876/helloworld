#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "tcp.h"

int lookup(char *host, char *portnr, struct addrinfo **res)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_protocol = 0;

	return getaddrinfo(host, portnr, &hints, res);
}

int connect_to(struct addrinfo *addr, struct timeval *rtt, int timeout)
{
	int fd;
	struct timeval start;
	int connect_result;
	const int on = 1;
	struct timeval tm;
	fd_set set;
	int flags;
	int ret;
	/* int flags; */
	int rv = 0;

	/* try to connect for each of the entries: */
	while (addr != NULL) {
		/* create socket */
		if ((fd =
		     socket(addr->ai_family, addr->ai_socktype,
			    addr->ai_protocol)) == -1)
			goto next_addr0;
		if (setsockopt
		    (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
			goto next_addr1;

		if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
			goto next_addr1;
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
			goto next_addr1;

		if (gettimeofday(&start, NULL) == -1)
			goto next_addr1;

		/* connect to peer */
		connect_result = connect(fd, addr->ai_addr, addr->ai_addrlen);
		if (connect_result == -1 && errno != EINPROGRESS) {
		  goto next_addr1;
		}
			
		tm.tv_sec  = timeout;
		tm.tv_usec = 0;

		FD_ZERO(&set);
		FD_SET(fd, &set);
		ret = select(fd+1, NULL, &set, NULL, &tm);
		switch(ret){
		case 0:/* timeout */
		case -1:
		  goto next_addr1;
		  break;
		default:/* Connection ok or refused*/
		  ret = write(fd, "", 0);/* only test, no data send */
		  if(ret <0) goto next_addr1;
		  break;
		}
		
		if (gettimeofday(rtt, NULL) == -1)
		  goto next_addr1;
		rtt->tv_sec = rtt->tv_sec - start.tv_sec;
		rtt->tv_usec = rtt->tv_usec - start.tv_usec;
		close(fd);
		return 0;
	
	next_addr1:
		close(fd);
	next_addr0:
		addr = addr->ai_next;
	}
	
	rv = rv ? rv : -errno;
	return rv;
}
