#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#ifdef __APPLE__
#   include <net/if_dl.h>
#   define AF_CUSTOM1 AF_LINK
#else
#   include <netinet/ether.h>
#   include <netinet/ip.h>
#   define AF_CUSTOM1 AF_PACKET
#endif

static int count = 0;

int handle_inet( const u_char *packet ) {

   struct ip *iptr = (struct ip *)packet;
   printf( "IP src = %s; IP dst = %s",
      inet_ntoa( iptr->ip_src ),
      inet_ntoa( iptr->ip_dst ) );
}

int handle_ethernet( const u_char *packet ) {

   struct ether_header *eptr = (struct ether_header *)packet;

   printf( "%d: type = ", count );

   int swapped = ntohs( eptr->ether_type );

   // there are more ether types than this, but I'm only handling ones
   // I expect to see

   switch( swapped ) {
   case ETHERTYPE_IP:
      handle_inet( packet + sizeof( struct ether_header ) );
      break;
   case ETHERTYPE_ARP:
      printf( "ARP" );
      break;
   case ETHERTYPE_REVARP:
      printf( "RARP" );
      break;
   case ETHERTYPE_VLAN:
      printf( "802.1Q" );
      break;
   case ETHERTYPE_IPV6:
      printf( "IPv6" );
      break;
   case ETHERTYPE_LOOPBACK:
      printf( "loopback" );
      break;
   default:
      printf( "0x%x", swapped );
      break;
   }

   printf( "; src MAC = %s; dst MAC = %s\n",
      ether_ntoa( (const struct ether_addr *)eptr->ether_shost ),
      ether_ntoa( (const struct ether_addr *)eptr->ether_dhost ) );
}

void callback( u_char *useless,
               const struct pcap_pkthdr *h,
               const u_char *packet ) {

   handle_ethernet( packet );
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
