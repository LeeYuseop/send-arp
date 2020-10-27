#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <signal.h>

#include <errno.h>


#include <net/if.h>

#include <sys/ioctl.h>

#include <netinet/ether.h>

#include <arpa/inet.h>

#include <unistd.h>


//debug define

#define DEBUG_LEVEL_	3


#ifdef  DEBUG_LEVEL_

#define dp(n, fmt, args...)	if (DEBUG_LEVEL_ <= n) fprintf(stderr, "%s:%d,"fmt, __FILE__, __LINE__, ## args)

#define dp0(n, fmt)		if (DEBUG_LEVEL_ <= n) fprintf(stderr, "%s:%d,"fmt, __FILE__, __LINE__)

#define _dp(n, fmt, args...)	if (DEBUG_LEVEL_ <= n) fprintf(stderr, " "fmt, ## args)

#else	/* DEBUG_LEVEL_ */

#define dp(n, fmt, args...)

#define dp0(n, fmt)

#define _dp(n, fmt, args...)

#endif	/* DEBUG_LEVEL_ */


int getIPAddress(char *ip_addr, char *dev);

int getMacAddress(char *mac, char *dev);

void convrt_mac(const char *data, char *cvrt_str, int sz);
