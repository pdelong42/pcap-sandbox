default: count myifcfg

count: count.c
	cc -o   count   count.c -lpcap

myifcfg: myifcfg.c
	cc -I/opt/local/include -o myifcfg myifcfg.c -lpcap

clean:
	rm -f count myifcfg
