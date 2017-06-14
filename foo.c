#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

int main( int argc, char **argv ) {

   char errbuf[PCAP_ERRBUF_SIZE];

   //printf( "first arg = %s\n", argv[1] );

   if( argv[1] == NULL ) {
      printf( "ERROR: first argument should be the pcap file - aborting\n" );
      exit( EXIT_FAILURE );
   }

   pcap_t *cap_data = pcap_open_offline( argv[1], errbuf );

   if( cap_data == NULL ) {
      printf( "ERROR: %s - aborting\n", errbuf );
      exit( EXIT_FAILURE );
   }

   printf( "Success opening %s\n", argv[1] );
   exit( EXIT_SUCCESS );
}
