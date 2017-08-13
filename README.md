This is my attempt to learn how to use libpcap.

Writing it in C seemed like the most sensible place to start.  Once
I've grasped the core concepts, I can move on to languages I'm more
comfortable in.  My initial intent was to do this in either Perl or
Clojure.

My C is super-rusty, so try not to judge too harshly.

ToDo:

 - pull yourself out of the rabbit-hole of re-implementing ifconfig,
   and get back to the goal of learning libpcap

 - figure-out how to use some of the newer sprintf() replacements, to
   implement safer string formatting, in order to pass strings up the
   call stack for printing at the top-level
