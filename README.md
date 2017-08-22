This is my attempt to learn how to use libpcap.

Writing it in C seemed like the most sensible place to start.  Once
I've grasped the core concepts, I can move on to languages I'm more
comfortable in.  My initial intent was to do this in either Perl or
Clojure.

My C is super-rusty, so try not to judge too harshly.

Contents:

 - count.c:

   This was the smallest meaningful test I could come up with of the
   minimum set of functinality from libpcap.  I figured counting the
   number of packets in a known packet-capture file was the easiest
   entry point, and I could verify it easily enough with common tools.
   If the count wasn't what I expected, I would know I was doing
   something wrong.

 - myifcfg.c:

   This was about me discovering some of the libpcap utility functions
   for enumerating devices and the info about the addresses bound to
   them.  I went down the rabbit hole and basically wrote my own basic
   version of ifconfig.

 - watch.c:

   This gets closer to my goal, of running a live loop and collecting
   statistics about which clients are making connections.  Currently,
   it's basically just a dumbed-down version of tcpdump; I don't
   really intend to implement more than a tiny subset of what that
   program does.  The intent is to collect stats in buckets, where the
   keys are unique tuples of addresses and ports; then I output the
   contents of those buckets on a regular polling interval, which is
   configurable.  Work-in-progress...
