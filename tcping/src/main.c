#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>

#include "tcp.h"

#define abs(x) ((x) < 0 ? -(x) : (x))

static volatile int stop = 0;

void usage(void)
{
	fprintf(stderr, "tcping version 0.3\n");

	fprintf(stderr,
		"Usage: tcping [-fqhv] [-p port] [-c count] [-i interval] [-t timeout] destination\n");
	fprintf(stderr,
		"-p port		Port number (default port 80)\n");
	fprintf(stderr, "-c count	How many times to connect\n");
	fprintf(stderr, "-i interval	Delay between each connect\n");
	fprintf(stderr, "-f		Flood connect (no delays)\n");
	fprintf(stderr, "-q		Quiet, only returncode\n");
	fprintf(stderr, "-t              Set timeout when connecting\n");
	fprintf(stderr, "-h		This help text\n");
}

void handler(int sig)
{
	fprintf(stderr, "\nreceive signal:[%d]\n", sig);
	stop = 1;
}

int main(int argc, char *argv[])
{
	char *hostname = NULL;
	char *portnr = "80";
	int c;
	int count = -1, curncount = 0;
	int wait = 1, quiet = 0;
	int ok = 0, err = 0;
	int timeout = 3;
	double min = 999999999999999.0, avg = 0.0, max = 0.0;
	struct addrinfo *resolved;
	int errcode;
	int seen_addrnotavail;

	while ((c = getopt(argc, argv, "t:hp:c:i:fq?")) != -1) {
		switch (c) {
		case 'p':
			portnr = optarg;
			break;

		case 'c':
			count = atoi(optarg);
			break;

		case 't':
            	        timeout = atoi(optarg);
		        break;

		case 'i':
			wait = atoi(optarg);
			break;

		case 'f':
			wait = 0;
			break;

		case 'q':
			quiet = 1;
			break;

		case '?':
		default:
			usage();
			return 0;
		}
	}

	if (optind >= argc) {
	  /*
		fprintf(stderr, "No hostname given\n");
	  */
		usage();
		return 3;
	}
	hostname = argv[optind];

	signal(SIGINT, handler);
	signal(SIGTERM, handler);

	if ((errcode = lookup(hostname, portnr, &resolved)) != 0) {
		fprintf(stderr, "%s\n", gai_strerror(errcode));
		return 2;
	}

	if (!quiet)
		printf("TCPING %s:%s\n", hostname, portnr);

	while ((curncount < count || count == -1) && stop == 0) {
		double ms;
		struct timeval rtt;

		if ((errcode = connect_to(resolved, &rtt, timeout)) != 0) {
			if (errcode != -EADDRNOTAVAIL) {
				printf
				    ("error connecting to host (%d): %s",
				     -errcode, strerror(-errcode));
				if(-errcode == EINPROGRESS){
				  printf(" [Timeout]\n");
				}else{
				  printf("\n");
				}
				err++;
			} else {
				if (seen_addrnotavail) {
					printf(".");
					fflush(stdout);
				} else {
					printf
					    ("error connecting to host (%d): %s\n",
					     -errcode, strerror(-errcode));
				}
				seen_addrnotavail = 1;
			}
		} else {
			seen_addrnotavail = 0;
			ok++;

			ms = ((double) rtt.tv_sec * 1000.0) +
			    ((double) rtt.tv_usec / 1000.0);
			avg += ms;
			min = min > ms ? ms : min;
			max = max < ms ? ms : max;

			printf
			    ("response from %s:%s, seq=%d time=%.2f ms\n",
			     hostname, portnr, curncount, ms);
			if (ms > 500)
				break;	/* Stop the test on the first long connect() */
		}

		curncount++;

		if (curncount != count)
			sleep(wait);
	}

	if (!quiet) {
		printf("--- %s:%s tcping statistics ---\n", hostname,
		       portnr);
		printf("%d responses, %d ok, %3.2f%% failed\n", curncount,
		       ok,
		       (((double) err) / abs(((double) count)) * 100.0));
		printf("round-trip min/avg/max = %.1f/%.1f/%.1f ms\n", min,
		       avg / (double) ok, max);
	}

	freeaddrinfo(resolved);
	if (ok)
		return 0;
	else
		return 127;
}
