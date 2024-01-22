//
// Created by Павел on 15.01.2024.
//
#include <string>
#include <iostream>
#include <map>
#include <sstream>
#include <fstream>
#include "./pcap/pcap.h"

using namespace std;

struct pcap_pkthdr *header;

const unsigned char *data;

// 4 bytes IP address
typedef struct ip_address {
    unsigned char byte1;
    unsigned char byte2;
    unsigned char byte3;
    unsigned char byte4;
} ip_address;


// 20 bytes IP Header
typedef struct ip_header {
    unsigned char ver_ihl;
    unsigned char tos;
    unsigned short tlen;
    unsigned short identification;
    unsigned short flags_fo;
    unsigned char ttl;
    unsigned char proto;
    unsigned short crc;
    ip_address saddr;
    ip_address daddr;
} ip_header;

typedef struct tcp_header {
    unsigned short sport; // Source port
    unsigned short dport; // Destination port
    unsigned int seqnum; // Sequence Number
    unsigned int acknum; // Acknowledgement number
    unsigned char th_off; // Header length
    unsigned char flags; // packet flags
    unsigned short win; // Window size
    unsigned short crc; // Header Checksum
    unsigned short urgptr;

} tcp_header;

int size_ip = 14;
int SIZE_ETHERNET = 14;
const struct ip_header *ip;
const struct tcp_header *tcp;
stringstream ss;
string stream;
map<string, pair<int, int>> streams;

int main() {
    string ncap_file;
    cout << "Input filepath >>" << endl;
    cin >> ncap_file;

    char errbuff[PCAP_ERRBUF_SIZE];

    pcap_t *pcap = pcap_open_offline(ncap_file.c_str(), errbuff);

    if (pcap == NULL) {
        cout << "Can't open file" << endl;
        return 0;
    }

    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {
        ip = (struct ip_header *) (data + size_ip);
        if ((ip->proto != 17) & (ip->proto != 6)) {
            continue;
        }
        tcp = (struct tcp_header *) (data + SIZE_ETHERNET + size_ip);


        ss << int(ip->saddr.byte1) << "." << int(ip->saddr.byte2) << "." << int(ip->saddr.byte3) << "."
           << int(ip->saddr.byte4);
        ss << "," << int(ip->daddr.byte1) << "." << int(ip->daddr.byte2) << "." << int(ip->daddr.byte3) << "."
           << int(ip->daddr.byte4);
        ss << "," << tcp->sport << "," << tcp->dport;
        stream = ss.str();

        if (streams.count(stream) == 0) {
            streams[stream] = make_pair(1, header->len);
        } else {
            streams[stream].first += 1;
            streams[stream].second += header->len;
        }
        ss.str("");
    }
    ofstream file("data.csv");
    if (file.is_open()) {
        for (const auto &pair :streams) {
            file << pair.first << "," << pair.second.first << "," << pair.second.second << endl;
        }
        file.close();
    } else {
        cout << "Cant open file" << endl;
    }
    cout << "Done" << endl;
    return 0;
}

