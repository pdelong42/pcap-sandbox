default: count myifcfg watch

count: count.c
	cc -o   count   count.c -lpcap

myifcfg: myifcfg.c
	cc -o myifcfg myifcfg.c -lpcap

watch: watch.c
	cc -o   watch   watch.c -lpcap

clean:
	rm -f count myifcfg watch
