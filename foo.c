#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

int main( int argc, char **argv ) {

   char errbuf[PCAP_ERRBUF_SIZE];

   //printf( "first arg = %s\n", argv[1] );

   if( argv[1] == NULL ) {
      printf( "aborting: first arg is null - please provide pcap file\n" );
      exit( EXIT_FAILURE );
   }

   pcap_t *cap_data = pcap_open_offline( argv[1], errbuf );
}
