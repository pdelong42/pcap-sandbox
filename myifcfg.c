#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef __APPLE__
#   include <net/if_dl.h>
#   define AF_CUSTOM1 AF_LINK
#   define MAC_NTOA link_ntoa
#   define MAC_NTOA_STR "link_ntoa"
#   define MAC_SOCKADDR sockaddr_dl
#else
#   include <netinet/ether.h>
#   define AF_CUSTOM1 AF_PACKET
#   define MAC_NTOA ether_ntoa
#   define MAC_NTOA_STR "ether_ntoa"
#   define MAC_SOCKADDR ether_addr
#endif

void print_description( char *description ) {
   if( description == NULL ) return;
   printf( "\tdescription: %s\n", description );
}

void print_inet_addr( struct sockaddr_in *inet_addr ) {

   char *ip = inet_ntoa( inet_addr->sin_addr );

   if( ip == NULL ) {
      perror( "inet_ntoa" );
      return;
   }

   printf( "\tIP: %s\n", ip );
}

void print_inet6_addr( struct sockaddr_in6 *inet_addr ) {

   char *addr = (char *)&inet_addr->sin6_addr;
   char *ip = malloc( INET6_ADDRSTRLEN * sizeof(char) );

   if( ip == NULL ) {
      perror( "malloc" );
      return;
   }

   // this feels like a terrible hack
   ip = (char *)inet_ntop( AF_INET6, addr, ip, INET6_ADDRSTRLEN );

   if( ip == NULL ) {
      perror( "inet_ntop" );
      return;
   }

   printf( "\tIPv6: %s\n", ip );
   free( ip );
}

void print_link_addr( struct sockaddr *addr ) {

   char *mac = MAC_NTOA( (struct MAC_SOCKADDR *)addr );

   if( mac == NULL ) {
      perror( MAC_NTOA_STR );
      return;
   }

   printf( "\tMAC: %s\n", mac );
}

//void print_link_addr( void *link_addr ) {
//   printf( "\nMAC: unimplemented\n" );
//}

void print_current_address( struct sockaddr *address ) {

   sa_family_t family = address->sa_family;

   switch( family ) {

   case AF_INET:
      print_inet_addr( (struct sockaddr_in *)address );
      break;

   case AF_INET6:
      print_inet6_addr( (struct sockaddr_in6 *)address );
      break;

   case AF_CUSTOM1:
      print_link_addr( address );
      break;

   default:
      printf( "\tunrecognized address family %d\n", family );
   }
}

void print_remaining_addresses( pcap_addr_t *address ) {

   if( address == NULL ) return;

   print_current_address(     address->addr );
   print_remaining_addresses( address->next );
}

void print_flags( int flags ) {

   if( ~flags ) return;
   printf( "\tflags:" );
   if( flags & PCAP_IF_LOOPBACK ) printf( " LOOPBACK" );
#ifndef __APPLE__
   if( flags & PCAP_IF_UP )       printf( " UP" );
   if( flags & PCAP_IF_RUNNING )  printf( " RUNNING" );
#endif
   printf( "\n" );
}

void print_remaining_devices( pcap_if_t *dev_p ) {

   if( dev_p == NULL ) return;

   printf( "name: %s\n", dev_p->name );

   print_description(         dev_p->description );
   print_remaining_addresses( dev_p->addresses   );
   print_flags(               dev_p->flags       );
   print_remaining_devices(   dev_p->next        );
}

int main( int argc, char **argv ) {

   char errbuf[PCAP_ERRBUF_SIZE];

   pcap_if_t *dev_p;

   int ret = pcap_findalldevs( &dev_p, errbuf );

   if( ret == -1 || ret != 0 ) {
      printf( "ERROR: %s - aborting\n", errbuf );
      exit( EXIT_FAILURE );
   }

   print_remaining_devices( dev_p );

   pcap_freealldevs( dev_p );

   exit( EXIT_SUCCESS );
}
