#include "net.h"

int getIPAddress(char *ip_addr, char *dev)

{

	int sock;

	struct ifreq ifr;

	struct sockaddr_in *sin;

	

	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock < 0) 

	{

//		dp(4, "socket");

		return -1;

	}


	strcpy(ifr.ifr_name, dev);

	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0)    

	{

//		dp(4, "ioctl() - get ip");

		close(sock);

		return 0;

	}

	

	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	strcpy(ip_addr, inet_ntoa(sin->sin_addr));

	

	close(sock);

	return 1;

}



int getMacAddress(char *mac, char *dev)

{

	int sock;

	struct ifreq ifr;

	char mac_adr[18] = {0,};

	

	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock < 0) 

	{

//		dp(4, "socket");

		return 0;

	}


	strcpy(ifr.ifr_name, dev);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0)    

	{

//		dp(4, "ioctl() - get mac");

		close(sock);

		return 0;

	}

	

	//convert format ex) 00:00:00:00:00:00

	convrt_mac( ether_ntoa((struct ether_addr *)(ifr.ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr) -1 );

	 

	strcpy(mac, mac_adr);

	

	close(sock);

	return 1;

}



void convrt_mac(const char *data, char *cvrt_str, int sz)

{

     char buf[128] = {0,};

     char t_buf[8];

     char *stp = strtok( (char *)data , ":" );

     int temp=0;


     do

     {

          memset( t_buf, 0, sizeof(t_buf) );

          sscanf( stp, "%x", &temp );

          snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );

          strncat( buf, t_buf, sizeof(buf)-1 );

          strncat( buf, ":", sizeof(buf)-1 );

     } while( (stp = strtok( NULL , ":" )) != NULL );


     buf[strlen(buf) -1] = '\0';

     strncpy( cvrt_str, buf, sz );

}
