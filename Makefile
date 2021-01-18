all: pcap-stat

pcap-stat:
	g++ -o pcap-stat main.cpp -lpcap

clean:
	rm pcap-stat
