#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

static int count = 0;

void callback( u_char *useless,
               const struct pcap_pkthdr *h,
               const u_char *bytes ) {
   ++count;
}

int main( int argc, char **argv ) {

   char errbuf[PCAP_ERRBUF_SIZE];

   if( argv[1] == NULL ) {
      printf( "ERROR: first argument should be the pcap file - aborting\n" );
      exit( EXIT_FAILURE );
   }

   pcap_t *cap_data = pcap_open_offline( argv[1], errbuf );

   if( cap_data == NULL ) {
      printf( "ERROR: %s - aborting\n", errbuf );
      exit( EXIT_FAILURE );
   }

   int ret = pcap_loop( cap_data, 0, callback, NULL );

   if( ret == -1 ) {
      printf( "ERROR: %s - aborting\n", errbuf );
      exit( EXIT_FAILURE );
   }

   if( ret == -2 ) {
      printf( "ERROR: this should not happen, I never call pcap_breakloop() - aborting\n" );
      exit( EXIT_FAILURE );
   }

   printf( "Successfully counted %d packets\n", count );
   exit( EXIT_SUCCESS );
}
