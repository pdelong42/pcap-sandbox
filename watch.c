#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef __APPLE__
#   include <net/if_dl.h>
#   define AF_CUSTOM1 AF_LINK
#else
#   include <netinet/ether.h>
#   define AF_CUSTOM1 AF_PACKET
#endif

static int count = 0;

char *strdub( const char *src ) {

   char *dst = strdup( src );

   if( dst == NULL ) {
      perror( "strdup" );
      exit( EXIT_FAILURE );
   }

   return( dst );
}

char *dynamic_printf( const char *fmt, ... ) {

   int ret;
   va_list ap;
   char *stringp_out;

   va_start( ap, fmt );
   ret = vasprintf( &stringp_out, fmt, ap );
   va_end( ap );

   if( ret < 0 ) {
      printf( "allocation error - exiting" );
      exit( EXIT_FAILURE );
   }

   return( stringp_out );
}

char *handle_transport_undef( int ip_type ) {
   return( dynamic_printf( "unhandled iptype: 0x%x", ip_type ) );
}

char *handle_transport_minimal( const char *label ) {
   return( strdub( label ) );
}

char *handle_transport_tcp( const u_char *packet ) {

   struct tcphdr *header = (struct tcphdr *)packet;

   return(
      dynamic_printf(
         "TCP src = %d; TCP dst = %d",
         ntohs( header->th_sport ),
         ntohs( header->th_dport ) ) );
}

char *handle_transport_udp( const u_char *packet ) {

   struct udphdr *header = (struct udphdr *)packet;

   return(
      dynamic_printf(
         "UDP src = %d; UDP dst = %d",
         ntohs( header->uh_sport ),
         ntohs( header->uh_dport ) ) );
}

char *handle_transport_generic( const u_char *payload, int type ) {

   // there are more IP types than these, but I'm only handling the
   // ones I expect to see

   switch( type ) {
   case IPPROTO_TCP:
      return( handle_transport_tcp( payload ) );
   case IPPROTO_UDP:
      return( handle_transport_udp( payload ) );
   case IPPROTO_ICMPV6:
      return( handle_transport_minimal( "ICMPv6" ) );
   default:
      return( handle_transport_undef( type ) );
   }
}

char *handle_network_undef( int ether_type ) {
   return( dynamic_printf( "unhandled ethertype: 0x%x", ether_type ) );
}

char *handle_network_minimal( const char *label ) {
   return( strdub( label ) );
}

char *handle_network_inet( const u_char *packet ) {

   struct ip *header = (struct ip *)packet;

   char *stringp_in1 = strdub( inet_ntoa( header->ip_src ) );
   char *stringp_in2 = strdub( inet_ntoa( header->ip_dst ) );
   char *stringp_in3 = handle_transport_generic(
      packet + sizeof( struct ip ),
      header->ip_p );
   
   char *stringp_out = dynamic_printf(
      "IP src = %s; IP dst = %s; %s",
      stringp_in1,
      stringp_in2,
      stringp_in3 );

   free( stringp_in1 );
   free( stringp_in2 );
   free( stringp_in3 );

   return( stringp_out );
}

char *stringify_inet6_addr( struct in6_addr *addr ) {

   char *ip = malloc( INET6_ADDRSTRLEN * sizeof(char) );

   if( ip == NULL ) {
      perror( "malloc" );
      exit( EXIT_FAILURE );
   }

   // this feels like a terrible hack
   ip = (char *)inet_ntop( AF_INET6, addr, ip, INET6_ADDRSTRLEN );

   if( ip == NULL ) {
      perror( "inet_ntop" );
      exit( EXIT_FAILURE );
   }

   char *stringp_out = strdub( ip );

   free( ip );

   return( stringp_out );
}

char *handle_network_ipv6( const u_char *packet ) {

   struct ip6_hdr *header = (struct ip6_hdr *)packet;

   char *stringp_in1 = stringify_inet6_addr( &header->ip6_src );
   char *stringp_in2 = stringify_inet6_addr( &header->ip6_dst );

   char *stringp_in3 = handle_transport_generic(
      packet + sizeof( struct ip6_hdr ),
      header->ip6_nxt );

   char *stringp_out = dynamic_printf(
      "IPv6 src = %s; IPv6 dst = %s; %s",
      stringp_in1,
      stringp_in2,
      stringp_in3 );

   free( stringp_in1 );
   free( stringp_in2 );
   free( stringp_in3 );

   return( stringp_out );
}

char *handle_network_generic( const u_char *payload, int swapped ) {

   // there are more ether types than these, but I'm only handling the
   // ones I expect to see

   switch( swapped ) {
   case ETHERTYPE_IP:
      return( handle_network_inet( payload ) );
   case ETHERTYPE_ARP:
      return( handle_network_minimal( "ARP" ) );
   case ETHERTYPE_REVARP:
      return( handle_network_minimal( "RARP" ) );
   case ETHERTYPE_VLAN:
      return( handle_network_minimal( "802.1Q" ) );
   case ETHERTYPE_IPV6:
      return( handle_network_ipv6( payload ) );
   case ETHERTYPE_LOOPBACK:
      return( handle_network_minimal( "loopback" ) );
   default:
      return( handle_network_undef( swapped ) );
   }
}

char *ether_ntoa_nostatic( u_char *ether_host ) {
   return( strdub( ether_ntoa( (const struct ether_addr *)ether_host ) ) );
}

char *handle_ethernet( const u_char *packet ) {

   struct ether_header *header = (struct ether_header *)packet;

   char *stringp_in1 = ether_ntoa_nostatic( header->ether_shost );
   char *stringp_in2 = ether_ntoa_nostatic( header->ether_dhost );
   char *stringp_in3 = handle_network_generic(
      packet + sizeof( struct ether_header ),
      ntohs( header->ether_type ) );

   char *stringp_out = dynamic_printf(
      "MAC src = %s; MAC dst = %s; %s",
      stringp_in1,
      stringp_in2,
      stringp_in3 );

   free( stringp_in1 );
   free( stringp_in2 );
   free( stringp_in3 );

   return( stringp_out );
}

void callback( u_char *useless,
               const struct pcap_pkthdr *h,
               const u_char *packet ) {

   char *stringp_in = handle_ethernet( packet );
   printf( "%d: %s\n", count, stringp_in );
   free( stringp_in );
   ++count;
}

int main( int argc, char **argv ) {

   if( argv[1] == NULL ) {
      printf( "ERROR: first argument should be the device name - aborting\n" );
      exit( EXIT_FAILURE );
   }

   int timeout = 1000, snap = 4096, floozy = 1;
   char errbuf[PCAP_ERRBUF_SIZE] = "";
   pcap_t *handle = pcap_open_live( argv[1], snap, floozy, timeout, errbuf );

   if( handle == NULL ) {
      printf( "ERROR: %s - aborting\n", errbuf );
      exit( EXIT_FAILURE );
   }

   if( strncmp( errbuf, "", PCAP_ERRBUF_SIZE ) != 0 )
      printf( "WARNING: %s", errbuf );

   int ret = 0;

   while( ret >= 0 ) {
      ret = pcap_dispatch( handle, 0, callback, NULL );
      time_t now = time( NULL );
      printf( "epoch = %ld; delta = %d; total = %d\n", now, ret, count );
   }

   if( ret == -1 ) {
      printf( "ERROR: %s - aborting\n", errbuf );
      exit( EXIT_FAILURE );
   }

   if( ret == -2 ) {
      printf( "ERROR: this should not happen, I never call pcap_breakloop() - aborting\n" );
      exit( EXIT_FAILURE );
   }

   printf( "ERROR: unexpected return value of %d\n", ret );
   exit( EXIT_FAILURE );
}
