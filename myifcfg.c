#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void print_flags( int flags ) {

   if( ~flags ) return;
   printf( "\tflags:" );
   if( flags & PCAP_IF_LOOPBACK ) printf( " LOOPBACK" );
   //if( flags & PCAP_IF_UP )       printf( " UP" );
   //if( flags & PCAP_IF_RUNNING )  printf( " RUNNING" );
   // the manpage lies, on MacOS anyhow
   printf( "\n" );
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

   // this feels like a horrible hack
   ip = (char *)inet_ntop( AF_INET6, addr, ip, INET6_ADDRSTRLEN );

   if( ip == NULL ) {
      perror( "inet_ntop" );
      return;
   }

   printf( "\tIPv6: %s\n", ip );
}

void print_remaining_addresses( pcap_addr_t *address ) {

   if( address == NULL ) return;

   struct sockaddr *addr = address->addr;
   sa_family_t family = addr->sa_family;

   switch( family ) {

   case AF_INET:
      print_inet_addr( (struct sockaddr_in *)addr );
      break;

   case AF_INET6:
      print_inet6_addr( (struct sockaddr_in6 *)addr );
      break;

   default:
      printf( "\tunrecognized address family %d\n", family );
   }

   print_remaining_addresses( address->next );
}

void print_remaining_devices( pcap_if_t *dev_p ) {

   if( dev_p == NULL ) return;

   printf( "name: %s\n", dev_p->name );

   if( dev_p->description != NULL ) {
      printf( "description: %s\n", dev_p->description );
   }

   print_remaining_addresses( dev_p->addresses );
   print_flags( dev_p->flags );
   print_remaining_devices( dev_p->next );
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
