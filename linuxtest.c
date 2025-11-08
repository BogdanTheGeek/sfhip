#include <stdio.h>

#define HIP_PHY_HEADER_LENGTH_BYTES 4

#define SFHIP_IMPLEMENTATION
#include "sfhip.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <poll.h>

#define FAIL(x...) \
	{ fprintf( stderr, x ); exit( -5 ); }

int fdtap, fddev;

uint8_t mymac_dev[6];
uint8_t mymac_tap[6];

int sfhip_send_packet( sfhip * hip, sfhip_phy_packet * data, int length )
{
	if( length < 18 ) return -1;
	uint8_t * dpl = (uint8_t*)data;
	dpl[2] = dpl[16];
	dpl[3] = dpl[17];

#if 0
	printf( "TX %4d: ", length );
	for( int i = 0; i < length; i++ )
	{
		if( (i & 0xf) == 0 && i ) printf( "\n         " );
		printf( "%02x ", dpl[i] );
	}
	printf( "\n" );
#endif

	int usetaptun = 0;
	int offset = 0;
	int fd = fdtap;

	// Determine if the target MAC is the host's TAP device.
	if( memcmp( mymac_tap, dpl+4, 6 ) == 0 )
	{
		usetaptun = 1;
	}

	// For if we only have one device.
	if( !fdtap ) usetaptun = 0;
	if( !fddev ) usetaptun = 1;

	if( !usetaptun )
	{
		fd = fddev;
		offset = 4;
	}

	int sendlen = length - offset;
	int r = write( fd, dpl + offset, sendlen );
	if( r != sendlen )
	{
		fprintf( stderr, "Warning: write() failed with error %s\n", strerror( errno ) );
	}

	return 0;
}

typedef enum
{
	HTP_START,
	HTP_URL,
	HTP_POSTURL,
	HTP_BACKNEXP,
	HTP_LINEFIRST,
	HTP_LINE,
	HTP_BACKNEXPEND,
	HTP_REQUEST_COMPLETE,

	HTP_HEADER_REPLY_SENT,

	HTP_ERROR,
} httpparsestate;

typedef struct
{
	httpparsestate state : 8;
} http;

http https[SFHIP_TCP_SOCKETS];

void sfhip_got_dhcp_lease( sfhip * hip, sfhip_address addr )
{
	printf( "DHCP IP: " HIPIPSTR "\n", HIPIPV( addr ) );
}

int  sfhip_tcp_accept_connection( sfhip * hip, int sockno, int localport, hipbe32 remote_host )
{
	// return 0 to accept, -1 to abort.
	if( localport == 80 )
	{
		printf( "Got HTTP %d\n", sockno );
		http * h = https + sockno;
		h->state = HTP_START; 
		return 0;
	}
	else
	{
		printf( "Invalid port (%d)\n", localport );
		return -1;
	}
}

int  sfhip_tcp_got_data( sfhip * hip, int sockno, uint8_t * ip_payload, int ip_payload_length, int max_ip_payload )
{
	http * h = https + sockno;

	printf( "Got Data (%c)\n", ip_payload[0] );
	uint8_t c;
	uint8_t * p = ip_payload;
	uint8_t * end = p + ip_payload_length;
	httpparsestate s = h->state;
	while( p != end )
	{
		// TODO: Would be fun to make this a tiny table.
		c = *(p++);
		switch( s )
		{
		case HTP_START:
			if( c == ' ' ) s = HTP_URL;
			break;
		case HTP_URL:
			if( c == ' ' ) s = HTP_POSTURL;
			else if( c == '\r' ) s = HTP_BACKNEXP;
			else printf( "%c", c );
			break;
		case HTP_BACKNEXP:
			if( c == '\n' ) s = HTP_LINEFIRST;
			else s = HTP_ERROR;
			break;
		case HTP_LINEFIRST:
			if( c == '\r' ) s = HTP_BACKNEXPEND;
			else s = HTP_LINE;
			break;
		case HTP_POSTURL:
			if( c == '\r' ) s = HTP_BACKNEXP;
			break;
		case HTP_LINE:
			if( c == '\r' ) s = HTP_BACKNEXP;
			break;
		case HTP_BACKNEXPEND:
			if( c == '\n' ) s = HTP_REQUEST_COMPLETE;
			else s = HTP_ERROR;
			break;
		default:
			break;
		}
	}

	if( s == HTP_REQUEST_COMPLETE )
	{
		printf( "\nComplete\n" );
	}
	printf( "State: %d\n", s );
	h->state = s;
	return 0;
}

int  sfhip_tcp_send_done( sfhip * hip, int sockno, uint8_t * ip_payload, int max_ip_payload )
{
	http * h = https + sockno;

	printf( "Send Done\n" );
	if( h->state == HTP_REQUEST_COMPLETE )
		h->state = HTP_HEADER_REPLY_SENT;
	return 0;
}

void sfhip_tcp_socket_closed( sfhip * hip, int sockno )
{
	printf( "Socket Closed\n" );
}

int  sfhip_tcp_can_send( sfhip * hip, int sockno, uint8_t * ip_payload, int max_ip_payload, int retry )
{

	http * h = https + sockno;

	if( h->state == HTP_REQUEST_COMPLETE )
	{
		sprintf( ip_payload, "HTTP/1.0 200 OK\r\nContent-type: text/html\r\n\r\n" );
		return 1460;
	}
	else if( h->state == HTP_HEADER_REPLY_SENT )
	{
		return 1460;
	}
	else
	{
		return 0;
	}
/*
	static int c;
	ip_payload[0] = 'X';
	ip_payload[1] = '\n';
*/

/*
	c++;
	if( c & 1 )
		return 2;
	else
		return -1;
*/
}

int main( int argc, char ** argv )
{
	int64_t runtime = 0;

	printf( "Main started\n" );
	printf( "Link Force Symbol: %p\n", &sfhip_accept_packet );
	printf( "Link Force Symbol: %p\n", &sfhip_tick );
	printf( "Link Force Symbol: %p\n", &sfhip_send_packet );

	if( argc < 3 )
		goto failhelp;

	if( argc > 3 )
	{
		runtime = atoi( argv[3] ) * 1000ULL;
		printf( "Timing out after %ld ms\n", runtime );
	}

	fflush(stdout);

	#define TAP_ADDR "192.168.14.252"
	sfhip hip = {
		.ip =      HIPIP( 192, 168,  14, 251 ),
		.mask =    HIPIP( 255, 255, 255, 0   ),
		.gateway = HIPIP( 192, 168,  14, 1   ),
		.self_mac = { 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55 },
		.hostname = "sfhip_test_linux",
	};

	{
		const char * devname = argv[1];

		if( strcmp( devname, "-" ) == 0 )
		{
			fdtap = 0;
		}
		else
		{
			int istap = strncmp( devname, "tap", 3 ) == 0;
			int istun = strncmp( devname, "tun", 3 ) == 0;

			fdtap = open( "/dev/net/tun", O_RDWR );
			if( fdtap == -1 )
				FAIL( "Can't open dev net tap/tun\n" );

			struct ifreq ifr = { .ifr_flags = (istap?IFF_TAP:IFF_TUN) };

			strncpy(ifr.ifr_name, devname, IFNAMSIZ);

			if(( ioctl(fdtap, TUNSETIFF, (void*)&ifr)) == -1)
				FAIL("TUNSETIFF failed %s\n", strerror( errno ) );

			int sockup = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

			struct ifreq ifr_ifup = { 0 };
			ifr.ifr_flags = 0;
			((struct sockaddr_in *)&ifr.ifr_addr)->sin_family = AF_INET;
			((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = inet_addr(TAP_ADDR);
			if(( ioctl( sockup, SIOCSIFADDR, (void*)&ifr)) == -1 )
				FAIL( "SIOCSIFADDR failed %s\n", strerror(errno) );

			ifr_ifup.ifr_flags = (istap?IFF_TAP:IFF_TUN);
			strncpy(ifr_ifup.ifr_name, devname, IFNAMSIZ);
			ifr_ifup.ifr_flags = IFF_UP|IFF_BROADCAST|IFF_RUNNING|IFF_MULTICAST;
			if(( ioctl(sockup, SIOCSIFFLAGS, (void*)&ifr_ifup)) == -1)
				FAIL("SIOCSIFFLAGS failed %s\n", strerror( errno ) );
			if(( ioctl(sockup, SIOCSIFFLAGS, (void*)&ifr_ifup)) == -1)
				FAIL("SIOCSIFFLAGS failed %s\n", strerror( errno ) );


			// Also need to configrue its IP

			close( sockup );

			struct ifreq ifr_mac = { 0 };
			if( ioctl( fdtap, SIOCGIFHWADDR, &ifr_mac ) < 0 )
			{
				FAIL( "Error: Couldn't get self-MAC\n" );
			}

			memcpy( mymac_tap, (char*)ifr_mac.ifr_hwaddr.sa_data, 6 );
		}
	}

	{
		const char * devname = argv[2];

		if( strcmp( devname, "-" ) == 0 )
		{
			fddev = 0;
		}
		else
		{
			fddev = socket( PF_PACKET, SOCK_RAW, htons(ETH_P_ALL) );

			struct ifreq if_idx;
			memset(&if_idx, 0, sizeof(struct ifreq));
			strncpy(if_idx.ifr_name, devname, IFNAMSIZ-1);
			if (ioctl(fddev, SIOCGIFINDEX, &if_idx) < 0)
			{
				fprintf( stderr, "Error: can't get index to interface [%s]\n", devname );
				return -1;
			}


			struct sockaddr_ll socket_address = {
				.sll_ifindex = if_idx.ifr_ifindex,
				.sll_halen = 0,
				.sll_family = AF_PACKET,
				.sll_protocol = htons(ETH_P_ALL),
				.sll_hatype = 0,
				.sll_pkttype = PACKET_BROADCAST,
			};

			if ( bind( fddev, (const struct sockaddr*)&socket_address, sizeof( socket_address ) ) < 0 )
				FAIL( "Cannot bind to %s\n", devname );

			// https://stackoverflow.com/questions/10070008/reading-from-pf-packet-sock-raw-with-read-misses-packets MAYBE?
			struct packet_mreq mr = {
				.mr_ifindex = socket_address.sll_ifindex,
				.mr_type = PACKET_MR_PROMISC,
			};

			if (setsockopt(fddev, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
				FAIL( "Error setting packet membership\n" );
			}

			struct ifreq ifr = { 0 };

			strncpy(ifr.ifr_name, devname, IFNAMSIZ-1);
			if( ioctl( fddev, SIOCGIFHWADDR, &ifr ) < 0 )
			{
				FAIL( "Error: Couldn't get self-MAC\n" );
			}

			memcpy( mymac_dev, (char*)ifr.ifr_hwaddr.sa_data, 6 );
			//setsockopt( fddev, SOL_SOCKET, SO_BINDTODEVICE, devname, strlen(devname) );
		}
	}

	uint64_t last_time = 0;
    struct timespec monotime;
    clock_gettime(CLOCK_MONOTONIC_RAW, &monotime);
	uint64_t ms = (monotime.tv_nsec/1000000ULL) + (monotime.tv_sec*1000ULL);
	last_time = ms;

	do
	{
		uint8_t buf[2048+4] HIPALIGN16 = { 0 };

		int nr_fds = (!!fddev) + (!!fdtap);

		struct pollfd fds[2] = { 0 };
		int i = 0;
		if( fddev )	{ fds[i].fd = fddev; fds[i].events = POLLIN; i++; }
		if( fdtap )	{ fds[i].fd = fdtap; fds[i].events = POLLIN; i++; }

		int r = poll( fds, nr_fds, 10 );
		if( r < 0 ) FAIL( "Fail on poll" );

		for( i = 0; i < nr_fds; i++ )
		{
			if( fds[i].fd && ( fds[i].revents & POLLIN ) )
			{
				int offset = ((fds[i].fd==fddev)?4:0);
				// If not a taptun device, add 4 bytes to the offset
				int r = read( fds[i].fd, buf + offset, 2048 );
				if( r < 0 )
					FAIL( "read() failed %s\n", strerror( errno ) );
				sfhip_accept_packet( &hip, (sfhip_phy_packet_mtu *)buf, r + offset );
			}
		}

	    clock_gettime(CLOCK_MONOTONIC_RAW, &monotime);
		uint64_t ms = (monotime.tv_nsec/1000000ULL) + (monotime.tv_sec*1000ULL);
		int delta_ms = ms - last_time;

		sfhip_phy_packet_mtu scratch;
		sfhip_tick( &hip, &scratch, delta_ms );
		
		if( runtime )
		{
			runtime -= delta_ms;
			if( runtime <= 0 ) return 0;
		}

		last_time = ms;

#if 0
		printf( "%4d: ", r );
		for( int i = 0; i < r; i++ )
		{
			if( (i & 0xf) == 0 && i ) printf( "\n      " );
			printf( "%02x ", buf[i] );
		}
		printf( "\n" );
#endif
				
	} while( 1 );

	return 0;
failhelp:
	FAIL( "Usage: [tool] [tunX|tapX|-] [ethernet_dev|-]\n" );
	return -1;
}

