#ifndef _SFHIP_H
#define _SFHIP_H

#include <stdint.h>

// General coding considerations:
//  1. Consider something like RISC-V where the first 5 parameters are passed
//     by a0..a4 registers.
//  2. Consider something like RV32E, where you only get 16 total registers, so
//     try to write the code to not register spill.  You can do this by writing
//     the code so at any one point, only a few variables are needed.
//  3. Think about compile-time perf by baking in easy-to-compile optimizations
//     i.e. when checking against a big endian number, take the BE of a 
//     constant instead of converting to host-local.
//
// Responsibilities:
//  1. The PHY layer is respoinsible for checking the 32-bit MAC CRC.
//  2. The PHY layer should pass in packets without the checksum at the end.

#ifndef HIP_PHY_HEADER_LENGTH_BYTES
#define HIP_PHY_HEADER_LENGTH_BYTES 0
#endif

#ifndef HIPSTATIC_ASSERT
#define HIPSTATIC_ASSERT _Static_assert
#endif


///////////////////////////////////////////////////////////////////////////////
// Internal

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	typedef uint16_t hipbe16;
	typedef uint32_t hipbe32;
	#define HIPHTONS(x) (x)
	#define HIPHTONL(x) (x)
	#define HIPNTOHS(x) (x)
	#define HIPNTOHL(x) (x)
#else
	#ifdef __CHECKER__
		#define __hipbitwise__ __attribute__((bitwise))
	#else
		#define __hipbitwise__
	#endif

	#ifdef __CHECK_ENDIAN__
		#define __hipbitwise __hipbitwise__
	#else
		#define __hipbitwise
	#endif
	typedef uint16_t __hipbitwise hipbe16;
	typedef uint32_t __hipbitwise hipbe32;
	#define HIPHTONS(x) ((((x)&0xff)<<8) | ((x)>>8))
	#define HIPHTONL(x) x
	#define HIPNTOHS(x) ((((x)&0xff)<<8) | ((x)>>8))
	#define HIPNTOHL(x) x
#endif

#define HIPALIGN32 __attribute__((aligned(4)))
#define HIPPACK32 HIPALIGN32 __attribute__((packed))
#define HIPPACK __attribute__((packed))

///////////////////////////////////////////////////////////////////////////////

// For fixed IPs, this compiles to a constant number.
#define HIPIP( a, b, c, d ) \
	HIPHTONL((((d)&0xff)<<24)|(((c)&0xff)<<16)|(((b)&0xff)<<8)|((a)&0xff))

#define HIPMACCOPY(a,b) { ((uint32_t*)a)[0] = ((uint32_t*)b)[0]; ((uint16_t*)a)[2] = ((uint16_t*)b)[2]; } 

typedef uint8_t hipmac[6];
typedef hipbe32 sfhip_address;

struct sfhip_ip_header
{
	uint8_t version_ihl;
	uint8_t dscp_ecn;
	hipbe16 length;
	hipbe16 identification;
	hipbe16 offset_and_flags;
	uint8_t ttl;
	uint8_t protocol;
	hipbe16 header_checksum;
	hipbe32 source_address;
	hipbe32 destination_address;
	// Possibly more fields, check IHL in flags.
} HIPPACK;

struct sfhip_mac_header
{
	hipmac destination;
	hipmac source;
	hipbe16 ethertype;
	//struct sfhip_ip_header ip_header HIPALIGN32;
	//struct sfhip_arp_header arp_header HIPALIGN32;
	// etc...
} HIPPACK;

#define HIPMACPAYLOAD( m )  (((void*)m)+14)

struct sfhip_phy_packet
{
	uint8_t phy_header[HIP_PHY_HEADER_LENGTH_BYTES];
	struct sfhip_mac_header mac_header;
} HIPPACK;

struct sfhip_udp_header
{
	hipbe16 source_port;
	hipbe16 destination_port;
	hipbe16 length;
	hipbe16 checksum;
} HIPPACK;

struct sfhip_arp_header
{
	hipbe16 hwtype;
	hipbe16 protocol;
	uint8_t hwlen;
	uint8_t protolen;
	hipbe16 operation;
	hipmac  sender;
	sfhip_address sproto;
	hipmac  target;
	sfhip_address tproto;	
} HIPPACK;

struct sfhip_icmp_header
{
	uint8_t type;
	uint8_t code;
	hipbe16 csum;
	hipbe16 identifier;
	hipbe16 sequence;
} HIPPACK;

struct sfhip_tcp_socket
{
	
};

struct sfhip
{
	hipmac self_mac;
	sfhip_address ip;
	sfhip_address mask;
	sfhip_address gateway;
	void * opaque;
};


// You must call.
int sfhip_accept_packet( struct sfhip * hip, struct sfhip_phy_packet * data, int length );

// You must implement.
int sfhip_send_packet( struct sfhip * hip, struct sfhip_phy_packet * data, int length );

// Constants
extern hipmac sfhip_mac_broadcast;


// Available functions

// Shortcuts to reply-to-sender.
int sfhip_mac_reply( struct sfhip * hip, struct sfhip_phy_packet * data, int length );
int sfhip_ip_reply( struct sfhip * hip, struct sfhip_phy_packet * data, int length );

hipbe16 internet_checksum( uint8_t * data, int length );




#ifdef SFHIP_IMPLEMENTATION

hipmac sfhip_mac_broadcast = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

int sfhip_mac_reply( struct sfhip * hip, struct sfhip_phy_packet * data, int length )
{
	struct sfhip_mac_header * mac = &data->mac_header;
	HIPMACCOPY( mac->destination, mac->source );
	HIPMACCOPY( mac->source, hip->self_mac );
	return sfhip_send_packet( hip, data, length );
}

int sfhip_ip_reply( struct sfhip * hip, struct sfhip_phy_packet * data, int length )
{
	struct sfhip_mac_header * mac = &data->mac_header;
	struct sfhip_ip_header * iph = (void*)(mac+1);
	iph->destination_address = iph->source_address;
	iph->source_address = hip->ip;
	return sfhip_mac_reply( hip, data, length );
}

hipbe16 sfhip_internet_checksum( uint16_t * data, int length )
{
	uint32_t sum = 0;
	int i;
	uint16_t * end = data + (length>>1);
	for( ; data != end; data++ )
		sum += *data;
	if( length & 1 )
		sum += *((uint8_t*)data);
	while( sum>>16 )
		sum = (sum & 0xffff) + (sum>>16);

	return ( ((uint16_t)~sum) );
}

int sfhip_handle_udp( struct sfhip * hip, struct sfhip_phy_packet * data, int length,
	void * ip_payload, int ip_payload_length )
{
	struct sfhip_udp_header * udp = ip_payload;

	int payload_remain = ip_payload_length - sizeof(struct sfhip_udp_header);

	if( payload_remain < 0 ) return -1;

	int ulen = HIPNTOHS( udp->length ) - 8;

	if( ulen > payload_remain || ulen < 0 )
	{
		// UDP packet too small
		printf( "Packet too small (%d) %d\n", payload_remain, ulen );
		return -1;
	}

	uint16_t * csumstart = ip_payload - 12;
	csumstart[0] = 17<<8;
	csumstart[1] = udp->length;
	uint16_t ccsum = sfhip_internet_checksum( csumstart, ip_payload_length + 12 );
	if( ccsum )
	{
		printf( "Failed UDP checksum [%04x]\n", ccsum );
		return -1;
	}

	printf( "Payload: %d\n", payload_remain );

	return 0;
}

int sfhip_accept_packet( struct sfhip * hip, struct sfhip_phy_packet * data, int length )
{
	// Make sure packet is not a runt frame.  This includes the PHY and etherlink frame.
	int payload_length = length - sizeof(struct sfhip_phy_packet);

	if( payload_length < 0 )
		return -1;

	struct sfhip_mac_header * mac = &data->mac_header;

	int ethertype_be = mac->ethertype;

	// Filter for IP4.
	if( ethertype_be == HIPHTONS( 0x0800 ) )
	{
		payload_length -= sizeof(struct sfhip_ip_header);

		if( payload_length < 0 )
			return -1;

		// Assume phy_header is opaque to us.
		struct sfhip_ip_header * iph = HIPMACPAYLOAD( mac );

		int hlen = (iph->version_ihl & 0xf)<<2;
		int version = iph->version_ihl >> 4;

		// Make sure it's a valid IPv4 header.
		if( hlen < 20 || version != 4 )
			return 0;

		int ip_payload_length = HIPNTOHS( iph->length ) - hlen;

		void * ip_payload = ((void*)iph) + hlen;

		payload_length -= hlen;

		// Check for packet overflow.
		if( ip_payload_length < payload_length )
			return -1;

		// Here, you have the following to work with:
		// ip_payload_length = payload length of internal IP packet, of UDP, for instance, need to subtract that.
		// ip_payload     = pointer to payload header, i.e. a UDP packet header.

		int protocol = iph->protocol;

		switch( protocol )
		{
		case 1: // IPPROTO_ICMP
		{
			if( ip_payload_length < sizeof( struct sfhip_icmp_header ) )
				return -1;

			struct sfhip_icmp_header * icmp = ip_payload;

			// Only handle requests, no replies yet.
			if( icmp->type == 8 )
			{
				icmp->type = 0;
				icmp->csum = 0;
				icmp->csum = sfhip_internet_checksum( ip_payload, ip_payload_length );
				sfhip_ip_reply( hip, data, length );
			}
			break;
		}
		case 17: // IPPROTO_UDP
		{
			return sfhip_handle_udp( hip, data, length, ip_payload, ip_payload_length );
		}
		default:
			break;
		}
	}
	else if( ethertype_be == HIPHTONS( 0x0806 ) )
	{
		// ARP packet
		struct sfhip_arp_header * arp = HIPMACPAYLOAD( mac );

		payload_length -= sizeof(struct sfhip_arp_header);

		if( payload_length < 0 )
			return -1;

		if( arp->operation == HIPHTONS( 0x01 ) )
		{
			// ARP request

			// TODO: Should we support broadcast replies?
			if( arp->tproto != hip->ip )
				return 0;

			// Edit ARP and send it back.
			HIPMACCOPY( arp->target, arp->sender );
			arp->tproto = arp->sproto;
			HIPMACCOPY( arp->sender, hip->self_mac );
			arp->sproto = hip->ip;
			arp->operation = HIPHTONS( 0x02 );

			return sfhip_mac_reply( hip, data, length );

		}
		else
		{
			// ARP reply (handle later, only useful when we are a client)
		}
	}
	else
	{
		// Other possible protocol, i.e. 0x86DD == IPv6
		//printf( "BE: %04x\n", ethertype_be );
	}

	return 0;
}

#endif

// Configuration asserts

HIPSTATIC_ASSERT( ((HIP_PHY_HEADER_LENGTH_BYTES)&3 ) == 0,
	"HIP_PHY_HEADER_LENGTH_BYTES must be divisible by 4" );

HIPSTATIC_ASSERT( sizeof( struct sfhip_phy_packet ) == sizeof( struct sfhip_mac_header ) + HIP_PHY_HEADER_LENGTH_BYTES, "phy packet misalignment" );
HIPSTATIC_ASSERT( sizeof( struct sfhip_mac_header ) == 14, "mac packet size incorrect" );
HIPSTATIC_ASSERT( sizeof( struct sfhip_arp_header ) == 28, "arp packet size incorrect" );


#endif

