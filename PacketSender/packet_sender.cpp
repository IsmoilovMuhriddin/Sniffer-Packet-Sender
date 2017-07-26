#include <stdio.h>
#include "pcap.h"
#define WIN32
#define WPCAP
#define HAVE_REMOTE
void print_raw_packet(const unsigned char *, int);

void print_ether_header(const unsigned char *);
void print_ip_header(const unsigned char *);
void print_tcp_header(const unsigned char *);
void print_data(const unsigned char *, int);

struct ether_addr {
	unsigned char ether_addr_octet[6];
};
struct  ether_header {
	struct  ether_addr ether_dhost;
	struct  ether_addr ether_shost;
	unsigned short ether_type;          // 0x0800 for IP
};
struct ip_hdr {
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;
	unsigned char ip_frag_offset : 5;
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	unsigned int ip_srcaddr;
	unsigned int ip_destaddr;
};
struct tcp_hdr {
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
};
int ETHER_HEADER_LEN = 14;
int IP_HEADER_LEN = 20;

int main() {
	pcap_if_t *alldevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	// find all network adapters
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("dev find failed\n");
		return -1;
	}
	if (alldevs == NULL) {
		printf("no devs found\n");
		return -1;
	}
	// print them
	pcap_if_t *d; int i;
	for (d = alldevs, i = 0; d != NULL; d = d->next) {
		printf("%d-th dev: %s ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	/*2*/
	int inum;
	printf("enter the interface number: ");
	scanf_s("%d", &inum);
	for (d = alldevs, i = 0; i<inum - 1; d = d->next, i++); // jump to the inum-th dev
															// open
	pcap_t  *fp;
	if ((fp = pcap_open_live(d->name,      // name of the device
		65536,                   // capture size
		1,  // promiscuous mode
		20,                    // read timeout
		errbuf
	)) == NULL) {
		printf("pcap open failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("pcap open successful\n");

	/*3*/
	struct bpf_program  fcode;
	if (pcap_compile(fp,  // pcap handle
		&fcode,  // compiled rule
		"host 165.246.38.152 and port 11044",  // filter rule
		1,            // optimize
		NULL) < 0) {
		printf("pcap compile failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(fp, &fcode) <0) {
		printf("pcap setfilter failed\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	pcap_freealldevs(alldevs); // we don't need this anymore

	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	int res;
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {// 1 if success
		if (res == 0) continue; // 0 if time-out
		print_raw_packet(pkt_data, header->caplen);
		print_ether_header(pkt_data);
		print_ip_header(pkt_data);
		print_tcp_header(pkt_data);
		print_data(pkt_data, header->caplen);
	}






	return 0;
}

/*
Printing  Data
*/
void print_raw_packet(const unsigned char *pkt_data, int len) {
	printf("\n-------raw packet ------\n");
	printf("pkt len: %d\n", len);
	for (int i = 0; i < len; i++)
	{
		printf("%2x ", pkt_data[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
}
void print_ether_header(const unsigned char *pkt_data) {
	printf("\n-------ether header------\n");
	ether_header *eh = (ether_header*)&pkt_data[0];
	ether_addr *eh_addr_d = (ether_addr*)&eh->ether_dhost;
	ether_addr *eh_addr_s = (ether_addr*)&eh->ether_shost;
	printf("destination ip address: %s\n", eh_addr_d->ether_addr_octet);
	printf("source ip address: %s\n ", eh_addr_s->ether_addr_octet);
	printf("source ip address: %d\n ", eh->ether_type);

}
void print_ip_header(const unsigned char *pkt_data) {
	printf("\n-------ip header------\n");
	ip_hdr *ih = (ip_hdr*)&pkt_data[14];
	printf("ip header len: %d ver: %d ", ih->ip_header_len * 4, ih->ip_version);

}
void print_tcp_header(const unsigned char *pkt_data) {
	printf("\n-------TCP HEADER ------\n");
	tcp_hdr *th = (tcp_hdr*)&pkt_data[34];
	printf("tcp header len: %d Source prot: %d Destination port %d", th->data_offset * 4, th->source_port, th->dest_port);
}
void print_data(const unsigned char *pkt_data, int len) {
	printf("\n-------raw packet ------\n");
	tcp_hdr *th = (tcp_hdr*)&pkt_data[34];
	int starting = 34 + th->data_offset * 4;

	for (int i = starting; i < len; i++)
	{
		printf("%2x ", pkt_data[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
}

/*
Building packet
*/
const unsigned char * buildPacket(const unsigned char *pkt_data) {




	return pkt_data;


}



/*
checksum
*/
unsigned short in_checksum(unsigned short *ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes>1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (SHORT)~sum;

	return(answer);
}

