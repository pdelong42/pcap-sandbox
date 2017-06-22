#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void process_device( pcap_if_t *dev_p ) {

   printf( "name: %s\n", dev_p->name );

   if( dev_p->description != NULL ) {
      printf( "description: %s\n", dev_p->description );
   }

   pcap_addr_t *address = dev_p->addresses;

   while( address != NULL ) {

      struct sockaddr_in *addr = (struct sockaddr_in *)address->addr;

      if( addr->sin_family != AF_INET ) {
         pcap_addr_t *temp_addr_p = address->next;
         address = temp_addr_p;
         continue;
      }

      char *ip = inet_ntoa( addr->sin_addr );

      if( ip == NULL ) {
         perror( "inet_ntoa" );
         exit( EXIT_FAILURE );
      }

      printf( "\tIP: %s\n", ip );

      pcap_addr_t *temp_addr_p = address->next;
      address = temp_addr_p;
   }

   int flags = dev_p->flags;

   if( flags )                    printf( "\tflags:" );
   if( flags & PCAP_IF_LOOPBACK ) printf( " LOOPBACK" );
   //if( flags & PCAP_IF_UP )       printf( " UP" );
   //if( flags & PCAP_IF_RUNNING )  printf( " RUNNING" );
   // the manpage lies, on MacOS anyhow
   printf( "\n" );
}

int main( int argc, char **argv ) {

   char errbuf[PCAP_ERRBUF_SIZE];

   pcap_if_t *current_dev_p;

   int ret = pcap_findalldevs( &current_dev_p, errbuf );

   pcap_if_t *first_dev_p = current_dev_p;

   if( ret == -1 || ret != 0 ) {
      printf( "ERROR: %s - aborting\n", errbuf );
      exit( EXIT_FAILURE );
   }

   while( current_dev_p != NULL ) {

      process_device( current_dev_p );
   
      pcap_if_t *temp_dev_p = current_dev_p->next;
      current_dev_p = temp_dev_p;
   }

   pcap_freealldevs( first_dev_p );

   exit( EXIT_SUCCESS );
}
