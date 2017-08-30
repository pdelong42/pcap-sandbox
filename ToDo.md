 - add the option of passing in pcap boolean expressions

 - fix all the error output to print to stderr as is proper

 - in watch.c, handle other cases in the handle_ethernet() switch statement
   (ARP, RARP, 802.1Q, IPv6 [done], and loopback);

 - [DONE] add a switch statement in handle_inet() and handle_ipv6()
   for descending deeper into transport-layer protocols (e.g., UDP,
   TCP, ICMP, etc.), but only handle a handful of them because there
   are lots;

 - decide whether to give the asprintf() treatment to myifcfg.c as
   well, or if it's fine as it stands

 - [DONE] pull yourself out of the rabbit-hole of re-implementing
   ifconfig, and get back to the goal of learning libpcap (implemented
   watch.c)

 - [DONE] figure-out how to use the relatively recent asprintf(), to
   implement safer string formatting, in order to pass strings up the
   call stack for printing at the top-level
