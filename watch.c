#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#ifdef __APPLE__
#   include <net/if_dl.h>
#   define AF_CUSTOM1 AF_LINK
#else
#   include <netinet/ether.h>
#   define AF_CUSTOM1 AF_PACKET
#endif

static int count = 0;

char *handle_undef( int ether_type ) {

   char *stringp_out;

   int ret = asprintf( &stringp_out, "unhandled ethertype: 0x%x", ether_type );

   if( ret < 0 ) {
      printf( "allocation error - exiting" );
      exit( EXIT_FAILURE );
   }

   return( stringp_out );
}

char *handle_minimal( const char *label ) {

   char *stringp_out;

   int ret = asprintf( &stringp_out, "%s", label );

   if( ret < 0 ) {
      printf( "allocation error - exiting" );
      exit( EXIT_FAILURE );
   }

   return( stringp_out );
}

char *handle_inet( const u_char *packet ) {

   char *stringp_out;
   struct ip *header = (struct ip *)packet;

   int ret = asprintf(
      &stringp_out,
      "IP src = %s; IP dst = %s",
      inet_ntoa( header->ip_src ),
      inet_ntoa( header->ip_dst ) );

   if( ret < 0 ) {
      printf( "allocation error - exiting" );
      exit( EXIT_FAILURE );
   }

   return( stringp_out );
}

char *stringify_inet6_addr( struct in6_addr *addr ) {

   char *stringp_out;
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

   int ret = asprintf( &stringp_out, "%s", ip );

   free( ip );

   if( ret < 0 ) {
      printf( "allocation error - exiting" );
      exit( EXIT_FAILURE );
   }

   return( stringp_out );
}

char *handle_ipv6( const u_char *packet ) {

   struct ip6_hdr *header = (struct ip6_hdr *)packet;
   char *stringp_in1 = stringify_inet6_addr( &header->ip6_src );
   char *stringp_in2 = stringify_inet6_addr( &header->ip6_dst );
   char *stringp_out;

   int ret = asprintf(
      &stringp_out,
      "IPv6 src = %s; IPv6 dst = %s",
      stringp_in1,
      stringp_in2 );

   free( stringp_in1 );
   free( stringp_in2 );

   if( ret < 0 ) {
      printf( "allocation error - exiting" );
      exit( EXIT_FAILURE );
   }

   return( stringp_out );
}

char *handle_ethernet( const u_char *packet ) {

   char *stringp_in, *stringp_out;
   struct ether_header *header = (struct ether_header *)packet;
   const u_char *payload = packet + sizeof( struct ether_header );
   int swapped = ntohs( header->ether_type );

   // there are more ether types than this, but I'm only handling the
   // ones I expect to see

   switch( swapped ) {
   case ETHERTYPE_IP:
      stringp_in = handle_inet( payload );
      break;
   case ETHERTYPE_ARP:
      stringp_in = handle_minimal( "ARP" );
      break;
   case ETHERTYPE_REVARP:
      stringp_in = handle_minimal( "RARP" );
      break;
   case ETHERTYPE_VLAN:
      stringp_in = handle_minimal( "802.1Q" );
      break;
   case ETHERTYPE_IPV6:
      stringp_in = handle_ipv6( payload );
      break;
   case ETHERTYPE_LOOPBACK:
      stringp_in = handle_minimal( "loopback" );
      break;
   default:
      stringp_in = handle_undef( swapped );
      break;
   }

   int ret = asprintf(
      &stringp_out,
      "MAC src = %s; MAC dst = %s; %s",
      ether_ntoa( (const struct ether_addr *)header->ether_shost ),
      ether_ntoa( (const struct ether_addr *)header->ether_dhost ),
      stringp_in );

   free( stringp_in );

   if( ret < 0 ) {
      printf( "allocation error - exiting" );
      exit( EXIT_FAILURE );
   }

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
