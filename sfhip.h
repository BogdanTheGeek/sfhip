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

#ifndef SFHIP_DHCP_CLIENT
#define SFHIP_DHCP_CLIENT 1
#endif

#ifndef SFHIP_MTU
#define SFHIP_MTU 1536
#endif

#ifndef SFHIP_CHECK_UDP_CHECKSUM
#define SFHIP_CHECK_UDP_CHECKSUM 1
#endif

#ifndef SFHIP_EMIT_UDP_CHECKSUM
#define SFHIP_EMIT_UDP_CHECKSUM 1
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
	#define HIPHTONL(x) ((((x)&0xff)<<24) | (((x)&0xff00)<<8)  | (((x)&0xff0000)>>8)  | (((x)&0xff000000)>>24))
	#define HIPNTOHS(x) ((((x)&0xff)<<8) | ((x)>>8))
	#define HIPNTOHL(x) ((((x)&0xff)<<24) | (((x)&0xff00)<<8)  | (((x)&0xff0000)>>8)  | (((x)&0xff000000)>>24))
#endif

#define HIPALIGN16          __attribute__((aligned(2)))
#define HIPPACK16           HIPALIGN16 __attribute__((packed))
#define HIPPACK             __attribute__((packed))

#define HIPMACSTR           "%02x:%02x:%02x:%02x:%02x:%02x"
#define HIPMACV( x )        x.mac[0], x.mac[1], x.mac[2], x.mac[3], x.mac[4], x.mac[5]

#define HIPIPSTR            "%d.%d.%d.%d"
#define HIPIPV( x )         (HIPNTOHL( x )>>24)&0xff, (HIPNTOHL( x )>>16)&0xff, (HIPNTOHL( x )>>8)&0xff, (HIPNTOHL( x )>>0)&0xff

#define HIPMACEQUAL( x, y ) (((uint16_t*)x.mac)[0] == ((uint16_t*)y.mac)[0] && ((uint16_t*)x.mac)[1] == ((uint16_t*)y.mac)[1] && ((uint16_t*)x.mac)[2] == ((uint16_t*)y.mac)[2] )
#define SFHIP_IPPROTO_UDP 17

///////////////////////////////////////////////////////////////////////////////

// For fixed IPs, this compiles to a constant number.
#define HIPIP( a, b, c, d ) \
	HIPHTONL((((d)&0xff)<<0)|(((c)&0xff)<<8)|(((b)&0xff)<<16)|(((a)&0xff)<<24))

typedef struct HIPPACK16
{
	uint8_t mac[6];
} hipmac;

typedef hipbe32 sfhip_address;

typedef struct HIPPACK16
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
} sfhip_ip_header;

typedef struct HIPPACK16
{
	hipmac destination;
	hipmac source;
	hipbe16 ethertype;
	//struct sfhip_ip_header ip_header HIPALIGN32;
	//struct sfhip_arp_header arp_header HIPALIGN32;
	// etc...
} sfhip_mac_header;

typedef struct HIPPACK16
{
	uint8_t phy_header[HIP_PHY_HEADER_LENGTH_BYTES];
	sfhip_mac_header mac_header;
} sfhip_phy_packet;

typedef struct HIPPACK16
{
	uint8_t phy_header[HIP_PHY_HEADER_LENGTH_BYTES];
	sfhip_mac_header mac_header;
	uint8_t payload[SFHIP_MTU - sizeof(sfhip_mac_header)];
} sfhip_phy_packet_mtu;

typedef struct HIPPACK16
{
	hipbe16 source_port;
	hipbe16 destination_port;
	hipbe16 length;
	hipbe16 checksum;
} sfhip_udp_header;

typedef struct HIPPACK16
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
} sfhip_arp_header;

typedef struct HIPPACK16
{
	uint8_t type;
	uint8_t code;
	hipbe16 csum;
	hipbe16 identifier;
	hipbe16 sequence;
} sfhip_icmp_header;

typedef struct
{
	
} sfhip_tcp_socket;

typedef struct
{
	void * opaque;

	hipmac self_mac;
	sfhip_address ip;
	sfhip_address mask;
	sfhip_address gateway;

	// This will wrap around.
	uint32_t ms_elapsed;

#if SFHIP_DHCP_CLIENT
	// if -1, has perma IP
	// max lease 24.9 days.
	int32_t dhcp_timer;
	uint32_t dhcp_transaction_id_last;
	const char * hostname;
#endif

	// Bitfileds go at end.
#if SFHIP_DHCP_CLIENT
	int need_to_discover : 1;
#endif

}  sfhip;

// You must call.
int sfhip_accept_packet( sfhip * hip, sfhip_phy_packet_mtu * data, int length );
void sfhip_tick( sfhip * hip, sfhip_phy_packet_mtu * scratch, int milliseconds );

// You must implement.
int sfhip_send_packet( sfhip * hip, sfhip_phy_packet * data, int length );

// Constants
extern hipmac sfhip_mac_broadcast;

// Available functions

// Shortcuts to reply-to-sender.
int sfhip_mac_reply( sfhip * hip, sfhip_phy_packet * data, int length );
int sfhip_ip_reply( sfhip * hip, sfhip_phy_packet * data, int length );

hipbe16 internet_checksum( uint8_t * data, int length );




#ifdef SFHIP_IMPLEMENTATION

hipmac sfhip_mac_broadcast = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

int sfhip_mac_reply( sfhip * hip, sfhip_phy_packet * data, int length )
{
	sfhip_mac_header * mac = &data->mac_header;
	mac->destination = mac->source;
	mac->source = hip->self_mac;
	return sfhip_send_packet( hip, data, length );
}

int sfhip_ip_reply( sfhip * hip, sfhip_phy_packet * data, int length )
{
	sfhip_mac_header * mac = &data->mac_header;
	sfhip_ip_header * iph = (void*)(mac+1);
	iph->destination_address = iph->source_address;
	iph->source_address = hip->ip;
	return sfhip_mac_reply( hip, data, length );
}

hipbe16 sfhip_internet_checksum( uint16_t * data, int length )
{
	uint32_t sum = 0;
	uint16_t * end = data + (length>>1);
	for( ; data != end; data++ )
		sum += *data;
	if( length & 1 )
		sum += *((uint8_t*)data);
	while( sum>>16 )
		sum = (sum & 0xffff) + (sum>>16);

	return ( ((uint16_t)~sum) );
}

void sfhip_make_ip_packet( sfhip * hip, sfhip_phy_packet_mtu * pkt, hipmac destination_mac, sfhip_address destination_address )
{
	// A little weird. We don't take on a source or destination port here.
	// No need to dirty up the ABI register allocation.
	sfhip_mac_header * mac = &pkt->mac_header;
	mac->destination = destination_mac;
	mac->source = hip->self_mac;
	mac->ethertype = HIPHTONS( 0x0800 );

	sfhip_ip_header * ip = (sfhip_ip_header *)(mac+1);
	ip->version_ihl = 0x45;
	ip->dscp_ecn = 0x00;
	ip->length = 0;
	ip->identification = 0x0000;

	// Do not initialize ttl, protocol or header_checksum, since they are 
	// used for the UDP pseduo-header checksum later.
	ip->offset_and_flags = 0x0000;
	ip->source_address = hip->ip;
	ip->destination_address = destination_address;
}

int sfhip_make_udp_packet( sfhip * hip, sfhip_phy_packet_mtu * pkt, hipmac destination_mac, sfhip_address destination_address, int source_port, int destination_port )
{
	sfhip_make_ip_packet( hip, pkt, destination_mac, destination_address );

	sfhip_mac_header * mac = &pkt->mac_header;
	sfhip_ip_header * ip = (sfhip_ip_header *)(mac+1);
	sfhip_udp_header * udp = (sfhip_udp_header *)(ip+1);

	udp->length = 0;
	udp->checksum = 0;
	udp->destination_port = HIPHTONS( destination_port );
	udp->source_port = HIPHTONS( source_port );

	return SFHIP_MTU - sizeof(sfhip_mac_header) - sizeof( sfhip_ip_header ) - sizeof( sfhip_udp_header );
}

int sfhip_send_udp_packet( sfhip * hip, sfhip_phy_packet_mtu * pkt, int payload_length )
{
	sfhip_ip_header * ip = (sfhip_ip_header *)( (&pkt->mac_header) +1);
	sfhip_udp_header * udp = (sfhip_udp_header *)(ip+1);

	ip->length = HIPHTONS( sizeof( sfhip_ip_header ) + sizeof( sfhip_udp_header ) + payload_length );
	udp->length = HIPHTONS( payload_length + sizeof( sfhip_udp_header ) );

	// Build and compute checksum on UDP pseudo-header in-place.
	uint16_t * csumstart = ((void*)udp) - 12;
	csumstart[0] = SFHIP_IPPROTO_UDP<<8;
	csumstart[1] = udp->length;

#if SFHIP_EMIT_UDP_CHECKSUM
	uint16_t udpcsum = sfhip_internet_checksum( (uint16_t*)csumstart, payload_length + sizeof( sfhip_udp_header) + 12  );
	if( udpcsum == 0x0000 ) udpcsum = 0xffff; // Per RFC 768, on send, if checksum is 0x0000, set it to 0xffff.
	udp->checksum = udpcsum;
#endif

	// Fixup overwritten pseudo header. Note these fields are never
	// initialized, so we have to initialize them here!!
	ip->ttl = 64;
	ip->protocol = SFHIP_IPPROTO_UDP;
	ip->header_checksum = 0;


	uint16_t hs = sfhip_internet_checksum( (uint16_t*)ip, sizeof( sfhip_ip_header ) );
	ip->header_checksum = hs;

	int packlen = payload_length + HIP_PHY_HEADER_LENGTH_BYTES + sizeof(sfhip_mac_header) + sizeof( sfhip_ip_header ) + sizeof( sfhip_udp_header );
	return sfhip_send_packet( hip, (sfhip_phy_packet*)pkt, packlen );
}


#if SFHIP_DHCP_CLIENT
void sfhip_dhcp_client_request( sfhip * hip, sfhip_phy_packet_mtu * scratch )
{
	// No matter what, we want to give the server time to respond.
	hip->dhcp_timer = 2048;

	typedef struct HIPPACK16
	{
		uint8_t phy_header[HIP_PHY_HEADER_LENGTH_BYTES];
		sfhip_mac_header mac_header;
		sfhip_ip_header  ip_header;
		sfhip_udp_header udp_header;
		uint8_t request;
		uint8_t hwtype;
		uint8_t hwlen;
		uint8_t hops;
		uint32_t transaction_id;
		hipbe16    seconds_elapsed;
		hipbe16    bootp_flags;
		sfhip_address client_address;
		sfhip_address next_address;
		sfhip_address next_server_address;
		sfhip_address relay_agent_address;
		hipmac client_mac;
		char macpadding[10];
		char server_name[64];
		char boot_name[128];
		hipbe32 magic_cookie;
		uint8_t additional_dhcp_payload[SFHIP_MTU-282];
	} sfhip_phy_packet_dhcp_request;

	uint32_t txid = hip->dhcp_transaction_id_last = hip->ms_elapsed;

	sfhip_phy_packet_dhcp_request * req_packet = (sfhip_phy_packet_dhcp_request*)scratch;

	*req_packet = (sfhip_phy_packet_dhcp_request){
		.request = 0x01, // "Request"
		.hwtype = 0x01,  // "Ethernet"
		.hwlen = 0x06,  // MAC Address length
		.hops = 0,
		.transaction_id = txid,
		.seconds_elapsed = HIPHTONS( 1 ),
		.bootp_flags = 0, // Unicast
		.client_address = hip->ip,
		.client_mac = hip->self_mac,
		.magic_cookie = HIPHTONL( 0x63825363 ), // DHCP magic cookie.
		.additional_dhcp_payload = {
			0x35, // DHCP Request
			0x01, // Length 1
			hip->need_to_discover ? 0x01 : 0x03, // Discover or request
			0x37, // Parameter Request List
			0x02, 0x01, 0x03, // Request subnet mask and router
		}
	};

	// 8 = size of additional_dhcp_payload that is filled out.
	uint8_t * dhcpend = req_packet->additional_dhcp_payload + 7;
	uint8_t * dhcpeof = (uint8_t*)(req_packet+1);

	// Need some free room.
	if( dhcpeof - dhcpend < 8 ) return;

	if( !hip->need_to_discover && hip->ip )
	{
		*(dhcpend++) = 0x32; // Request IP address
		*(dhcpend++) = 0x04;
 		*((uint32_t*)dhcpend) = hip->ip; // XXX TODO: Fixme: this will probably explode on ARM
		dhcpend+=4;
	}

	if( hip->hostname )
	{
		*(dhcpend++) = 0x0c;
		uint8_t * sstart = dhcpend++;
		const char * s = hip->hostname;
		char c;
		while( (c = *(s++)) != 0 )
		{
			*(dhcpend++) = c;
			if( dhcpeof - dhcpend < 3 ) return; // Make sure we don't overflow.
		}
		*sstart = dhcpend - sstart - 1;
	}

	*(dhcpend++) = 0xff; // DHCP end.

	int plen = (int)(dhcpend - (uint8_t*)&req_packet->request);

	sfhip_make_udp_packet( hip, (void*)req_packet, sfhip_mac_broadcast, 0xffffffff, 68, 67 );
	sfhip_send_udp_packet( hip, (sfhip_phy_packet_mtu*)req_packet, plen );
}

int sfhip_dhcp_handle( sfhip * hip, sfhip_phy_packet_mtu * original_packet, uint8_t * data, int length )
{
	typedef struct HIPPACK16
	{
		uint8_t request;
		uint8_t hwtype;
		uint8_t hwlen;
		uint8_t hops;
		uint32_t transaction_id;
		hipbe16    seconds_elapsed;
		hipbe16    bootp_flags;
		sfhip_address client_address;
		sfhip_address your_client_address;
		sfhip_address next_server_address;
		sfhip_address relay_agent_address;
		hipmac client_mac;
		char macpadding[10];
		char server_name[64];
		char boot_name[128];
		hipbe32 magic_cookie;
	} dhcp_reply;

	// Need +2 to be able to read the code + length for first
	// DHCP entry.
	if( length < sizeof( dhcp_reply ) + 2 ) return -1;

	dhcp_reply * d = (dhcp_reply*)data;

	// Make sure it's a bootp reply, and it's ours.
	if( d->request != 0x02 ||
		d->transaction_id != hip->dhcp_transaction_id_last ||
		d->magic_cookie != HIPHTONL( 0x63825363 ) ||
		!HIPMACEQUAL( d->client_mac, hip->self_mac ) ) return 0;

	uint32_t dhcp_ack_lease_time = 0;
	uint8_t  dhcp_type = 0;
	sfhip_address dhcp_offer_router = 0;
	sfhip_address dhcp_offer_mask = 0;

	uint8_t * dhcp = (uint8_t*)(d+1);
	uint8_t * dhcpend = (uint8_t*)(data) + length;
	do
	{
		uint8_t dhcp_code = *(dhcp++);
		uint8_t dhcp_length = *(dhcp++);
		if( dhcp + dhcp_length >= dhcpend ) break;

		uint32_t value = 0;
		int i = 0;
		for( i = 0; i < dhcp_length; i++ )
			value = (value<<8) | (uint32_t)dhcp[i];

		switch( dhcp_code )
		{
		case 53: 
		{
			// DHCP message type
			dhcp_type = dhcp[0];
			if( dhcp_type == 6 )
			{
				// NAK: If nak, try to get an IP without preconception.
				hip->need_to_discover = 1;

				// Re-request immediately.
				sfhip_dhcp_client_request( hip, original_packet );

				return 0;
			}
			// Offer = 2, Ack == 5
			break;
		}
		case 51: // Address lease time
		case 58: // Address renewal time  (prefer, if present)
			if( dhcp_code == 58 )
				dhcp_ack_lease_time = value;
			else if( dhcp_ack_lease_time == 0 )
				dhcp_ack_lease_time = value;
			break;
		case 1:   dhcp_offer_mask = HIPHTONL( value );    break;
		case 3:   dhcp_offer_router = HIPHTONL( value );  break;
		case 255: dhcp = dhcpend;                         break; // Force abort.
		};
		dhcp += dhcp_length;
	} while( dhcp + 2 < dhcpend );

	if( dhcp_type == 2 && dhcp_offer_router && dhcp_offer_mask && d->your_client_address )
	{
		hip->need_to_discover = 0;
		hip->ip = d->your_client_address;
		hip->mask = dhcp_offer_mask;
		hip->gateway = dhcp_offer_router;

		//printf( "IP   " HIPIPSTR "\nMASK " HIPIPSTR "\nGATE " HIPIPSTR "\n",
		//	 HIPIPV( hip->ip ), HIPIPV( hip->mask ), HIPIPV( hip->gateway ) );

		// Properly request.  Immediately.
		sfhip_dhcp_client_request( hip, original_packet );
	}

	if( dhcp_type == 5 )
	{
		// Lease is confirmed.

		// 2 hours (default lease time)
		if( dhcp_ack_lease_time == 0 )
			dhcp_ack_lease_time = 7200;

		// Make sure we don't overflow our timer for leasing.
		if( dhcp_ack_lease_time >= 2147482 )
			dhcp_ack_lease_time = 2147482;
			
		hip->dhcp_timer = dhcp_ack_lease_time * 1000;
	}
}

#endif

int sfhip_handle_udp( sfhip * hip, sfhip_phy_packet_mtu * data, int length,
	void * ip_payload, int ip_payload_length )
{
	sfhip_udp_header * udp = ip_payload;

	int payload_remain = ip_payload_length - sizeof(sfhip_udp_header);

	if( payload_remain < 0 ) return -1;

	int ulen = HIPNTOHS( udp->length ) - 8;

	if( ulen != payload_remain || ulen < 0 )
	{
		// UDP packet size does not match, or runt packet.
		return -1;
	}

#if SFHIP_CHECK_UDP_CHECKSUM
	if( udp->checksum )
	{
		// Build pseudo-header for checksum.
		uint16_t * csumstart = ip_payload - 12; // The UDP pseudo header checksum starts 5 bytes back.
		csumstart[0] = SFHIP_IPPROTO_UDP<<8;
		csumstart[1] = udp->length;
		uint16_t ccsum = sfhip_internet_checksum( csumstart, ulen + 20 );

		if( ccsum )
		{
			return -1;
		}
	}
#endif

	int source_port = HIPNTOHS( udp->source_port );
	int destination_port = HIPNTOHS( udp->destination_port );
	uint8_t * payload = (uint8_t*)(udp+1);

#if SFHIP_DHCP_CLIENT
	if( source_port == 67 && destination_port == 68 )
	{
		return sfhip_dhcp_handle( hip, data, payload, ulen );
	}
	else
#endif
	{
		// Do something else? Should we reply?
	}

	return 0;
}

int sfhip_accept_packet( sfhip * hip, sfhip_phy_packet_mtu * data, int length )
{
	// Make sure packet is not a runt frame.  This includes the PHY and etherlink frame.
	int payload_length = length - sizeof(sfhip_phy_packet);

	if( payload_length < 0 )
		return -1;

	sfhip_mac_header * mac = &data->mac_header;

	int ethertype_be = mac->ethertype;

	if( !(HIPMACEQUAL( mac->destination, sfhip_mac_broadcast ) || HIPMACEQUAL( mac->destination, hip->self_mac )))
	{
		//printf( "MEF" HIPMACSTR " "  HIPMACSTR "\n", HIPMACV( mac->destination ), HIPMACV( sfhip_mac_broadcast ) );
		return 0;
	}

	// Filter for IP4.
	if( ethertype_be == HIPHTONS( 0x0800 ) )
	{
		payload_length -= sizeof(sfhip_ip_header);

		if( payload_length < 0 )
			return -1;

		// Assume phy_header is opaque to us.
		sfhip_ip_header * iph = (void*)( mac+1 );

		int hlen = (iph->version_ihl & 0xf)<<2;
		int version = iph->version_ihl >> 4;

		// Make sure it's a valid IPv4 header.
		if( hlen < 20 || version != 4 )
			return 0;

		int ip_payload_length = HIPNTOHS( iph->length ) - hlen;

		void * ip_payload = ((void*)iph) + hlen;

		// Check for packet overflow.
		if( ip_payload_length > payload_length )
			return -1;

		payload_length -= hlen;

		// Here, you have the following to work with:
		// ip_payload_length = payload length of internal IP packet, of UDP, for instance, need to subtract that.
		// ip_payload     = pointer to payload header, i.e. a UDP packet header.

		int protocol = iph->protocol;

		switch( protocol )
		{
		case 1: // IPPROTO_ICMP
		{
			if( ip_payload_length < sizeof( sfhip_icmp_header ) )
				return -1;

			sfhip_icmp_header * icmp = ip_payload;

			// Only handle requests, no replies yet.
			if( icmp->type == 8 )
			{
				icmp->type = 0;
				icmp->csum = 0;
				icmp->csum = sfhip_internet_checksum( ip_payload, ip_payload_length );
				sfhip_ip_reply( hip, (sfhip_phy_packet*)data, length );
			}
			break;
		}
		case SFHIP_IPPROTO_UDP:
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
		sfhip_arp_header * arp = (void*)( mac+1 );

		payload_length -= sizeof(sfhip_arp_header);

		if( payload_length < 0 )
			return -1;

		if( arp->operation == HIPHTONS( 0x01 ) )
		{
			// ARP request

			// TODO: Should we support broadcast replies?
			if( arp->tproto != hip->ip )
				return 0;

			// Edit ARP and send it back.
			arp->target = arp->sender;
			arp->tproto = arp->sproto;
			arp->sender = hip->self_mac;
			arp->sproto = hip->ip;
			arp->operation = HIPHTONS( 0x02 );

			return sfhip_mac_reply( hip, (sfhip_phy_packet*)data, length );
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

void sfhip_tick( sfhip * hip, sfhip_phy_packet_mtu * scratch, int milliseconds )
{
#if SFHIP_DHCP_CLIENT
	int dhcp_time = hip->dhcp_timer;
	if( dhcp_time != -1 )
	{
		int next_time = dhcp_time - milliseconds;
		if( dhcp_time <= milliseconds )
		{
			// Request every second.
			if( next_time <= 0  )
			{
				sfhip_dhcp_client_request( hip, scratch );
				next_time = 2048;
			}
		}
		hip->dhcp_timer = next_time;
	}
#endif
	hip->ms_elapsed += milliseconds;
}

// Configuration asserts

HIPSTATIC_ASSERT( ((HIP_PHY_HEADER_LENGTH_BYTES)&3 ) == 0,
	"HIP_PHY_HEADER_LENGTH_BYTES must be divisible by 4" );

HIPSTATIC_ASSERT( sizeof( sfhip_phy_packet ) == sizeof( sfhip_mac_header ) + HIP_PHY_HEADER_LENGTH_BYTES, "phy packet misalignment" );
HIPSTATIC_ASSERT( sizeof( sfhip_mac_header ) == 14, "mac packet size incorrect" );
HIPSTATIC_ASSERT( sizeof( sfhip_arp_header ) == 28, "arp packet size incorrect" );

#endif

#endif

