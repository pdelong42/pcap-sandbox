#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main( int argc, char **argv ) {

   char errbuf[PCAP_ERRBUF_SIZE];
   bpf_u_int32 netp, maskp;

   char *dev = pcap_lookupdev( errbuf );

   if( dev == NULL ) {
      printf( "ERROR: %s - aborting\n", errbuf );
      exit( EXIT_FAILURE );
   }

   printf( "device = %s\n", dev );

   int ret = pcap_lookupnet( dev, &netp, &maskp, errbuf );

   if( ret == -1 ) {
      printf( "ERROR: %s - aborting\n", errbuf );
      exit( EXIT_FAILURE );
   }

   struct in_addr addr;

   addr.s_addr = netp;

   char *net = inet_ntoa( addr );

   if( net == NULL ) {
      perror( "inet_ntoa" );
      exit( EXIT_FAILURE );
   }

   printf( "network = %s\n", net );

   addr.s_addr = maskp;
   char *mask = inet_ntoa( addr );

   if( mask == NULL ) {
      perror( "inet_ntoa" );
      exit( EXIT_FAILURE );
   }
  
   printf( "netmask = %s\n", mask );

   exit( EXIT_SUCCESS );
}
