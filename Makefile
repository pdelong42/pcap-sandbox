default: count myifcfg

count: count.c
	cc -lpcap -o count   count.c

myifcfg: myifcfg.c
	cc -lpcap -o myifcfg myifcfg.c

clean:
	rm -f count myifcfg
