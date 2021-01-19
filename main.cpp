#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <map>
#include <netinet/in.h>
#include <arpa/inet.h>

class report_info
{
public:
	int tx_count;
	uint32_t tx_bytes;
	int rx_count;
	uint32_t rx_bytes;

	report_info()
	{
		this->tx_count = 0;
		this->tx_bytes = 0;
		this->rx_count = 0;
		this->rx_bytes = 0;
	}
	report_info(int tx_count, uint32_t tx_bytes, int rx_count, uint32_t rx_bytes)
	{
		this->tx_count = tx_count;
		this->tx_bytes = tx_bytes;
		this->rx_count = rx_count;
		this->rx_bytes = rx_bytes;
	}

};

bool check_ipv4(const u_char* packet)
{
	if(packet[12] == 0x08 && packet[13] == 0x00) return true;
	else false;
}

bool check_tcp(const u_char* packet)
{
	if(packet[23] == 0x06) return true;
	return false;
}

bool check_udp(const u_char* packet)
{
	if(packet[23] == 0x11) return true;
	return false;
}

uint32_t get_ip(const u_char* packet, bool send_or_dest)
{
	int shift = 0;
	// sender ip
	if(send_or_dest == true)
		shift = 26;
	// destination ip
	else
		shift = 30;
	
	uint32_t ret_ip = 0;
	for(int i=shift;i<shift+4;i++)
	{
		ret_ip <<= 8;
		ret_ip += packet[i];
	}
	return ret_ip;
}

char errbuf[PCAP_ERRBUF_SIZE];

std::map<uint32_t, report_info> report_mp;

int main(int argc, char* argv[])
{
	
	if(argc != 2)
	{
		printf("Systax pcap-stat <file>\n");
		printf("pcap-stat test.pcap\n");
		return -1;
	}

	pcap_t* test_pcap = pcap_open_offline(argv[1], errbuf);
	if(test_pcap == nullptr)
	{
		fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", argv[1], errbuf);
		return 2;
	}
	
	while(true)
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(test_pcap, &header, &packet);
		
		// if res == 1 -> The packet was read without problems.

		// Packets are being read from a live capture, and the timeout expired.
		if(res == 0) continue;
		
		// An error occurred while reading the packet.
		else if(res == -1)
		{
			fprintf(stderr, "Error occurred while reading the packet.\n%s\n", errbuf);
			break;
		}

		// packets are being read from a "savefile", and there are no more packets to read from the savefile.
		else if(res == -2)
		{
			printf("No more packets from savefile.\n");
			break;
		}

		
		if(check_ipv4(packet))
		{
			uint32_t send_ip = get_ip(packet, 1), dest_ip = get_ip(packet, 0);
		
		
			std::map<uint32_t, report_info>:: iterator send_it = report_mp.find(send_ip);
			std::map<uint32_t, report_info>:: iterator dest_it = report_mp.find(dest_ip);
			if(send_it == report_mp.end()) report_mp[send_ip] = report_info(1, header->caplen, 0, 0);
			else
			{
				report_mp[send_ip].tx_count++;
				report_mp[send_ip].tx_bytes += header->caplen;
			}
			if(dest_it == report_mp.end()) report_mp[dest_ip] = report_info(0, 0, 1, header->caplen);
			else
			{
				report_mp[dest_ip].rx_count++;
				report_mp[dest_ip].rx_bytes += header->caplen;
			}
		}
	}
	printf("Address\t\tPacket_count\tBytes\tTx_count\tTx_bytes\tRx_count\tRx_bytes\n");
	for(auto it=report_mp.begin();it!=report_mp.end();it++)
	{
		uint32_t address = it->first;
		report_info res_info = it->second;

		// Need change endianness.
		//printf("%s\n", inet_ntoa(*(struct in_addr *)&address));
		
		printf("%u.%u.%u.%u\t",(address>>24)%256, (address>>16)%256, (address>>8)%256, address%256);
		printf("%d\t\t%u\t", res_info.tx_count + res_info.rx_count, res_info.tx_bytes + res_info.rx_bytes);
		printf("%d\t\t%u\t\t", res_info.tx_count, res_info.tx_bytes);
		printf("%d\t\t%u\n", res_info.rx_count, res_info.rx_bytes);
	}

	pcap_close(test_pcap);
	return 0;
}
