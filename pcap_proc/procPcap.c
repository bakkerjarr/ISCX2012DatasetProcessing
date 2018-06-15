/*************************************************************************
* Copyright 2016 Jarrod N. Bakker
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* Makefile for the ISCX 2012 DDoS PCAP file processing program.
*
* FILENAME : procPcap.c
*
* DESCRIPTION :
*       This file uses XML data to filter PCAP data into a new PCAP file.
* 
* AUTHOR :  Jarrod N. Bakker    START DATE :    26/10/2016
*
**/

#include <pcap.h>
#include "commonUtil.h"
#include "procPcap.h"
/* Directives for processing packets. */
#include <arpa/inet.h> // Byte order conversion functions
#include <netinet/if_ether.h> // The Ethernet frame header
#include <netinet/ip.h>

static int processPkt(const unsigned char *rawPkt, const struct pcap_pkthdr rawHdr, xmlDoc *doc);
//static const char *timestamp_string(struct timeval ts);

/**
 * Create a new PCAP file 'output_pcap' by selecting packets in the
 * file 'input_pcap' that match flows in the XML 'doc'.
 * 
 * param input_pcap: Path of the input PCAP file.
 * param doc: XML information to filter by.
 * param output_pcap: Path of the new PCAP file.
 * return: 1 if successful, 0 otherwise.
 */
int filterPcap(char * input_pcap, xmlDoc *doc, char* ouput_pcap){
    char errbuf[PCAP_ERRBUF_SIZE];
    fprintf(stdout,"Opening PCAP data reader using file: %s\n", input_pcap);
    pcap_t *pcap = pcap_open_offline(input_pcap, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "ERROR: PCAP error: %s\n", errbuf);
        return 0;
    }
    
    const unsigned char *pkt;
    struct pcap_pkthdr header;
    //int i = 0;
    while ((pkt = pcap_next(pcap, &header)) != NULL) {
        //fprintf(stdout, "Packet timestamp: %s\n", timestamp_string(header.ts));
        //i++;
        //if (i == 9)
        //    break;
        /* Should the packet be included? */
        if (processPkt(pkt, header, doc)){
            // TODO: Write it to the new PCAP file.
        }
    }
    
    return 1;   
}

/**
 * Determine if the packet 'pkt' is part of a flow described in the
 * XML 'doc'.
 * 
 * Assumes that the packet uses Ethernet encapsulation.
 * 
 * param rawPkt: The packet to process.
 * param rawHdr: PCAP header of the packet.
 * param doc: XML information to filter by.
 * return: 1 if the packet is part of a flow, 0 otherwise.
 */
static int processPkt(const unsigned char *rawPkt, 
                      const struct pcap_pkthdr rawHdr, xmlDoc *doc){
    const unsigned char *pkt = rawPkt;
    struct pcap_pkthdr hdr = rawHdr;
    /* The packet should be larger than the Ethernet header. */
    if (hdr.caplen < sizeof(struct ether_header)){
        return 0;
    }
    
    /* Include non-IP packets as they are not part of any flow */
    /* in the XML file. They form part of the background traffic. */
    const struct ether_header *eth = (struct ether_header*) pkt;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return 1;
    }
    
    /* Move to the IP header */
    pkt += sizeof(struct ether_header);
    hdr.caplen -= sizeof(struct ether_header);
    struct ip *ip = (struct ip*) pkt;
    unsigned int ip_hl = ip->ip_hl * 4; // ip_hl is the number of 4-byte words
    
    /* The Ethernet payload should be larger than the IP header. */
    if (hdr.caplen < ip_hl) {
        return 0;
    }
    
    // TODO: Get transport protocol, and port numbers.
    
    return 0;
}

/**
 * This function has been adapted from: 
 * http://inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c
 * 
 * Note: this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
/*
static const char *timestamp_string(struct timeval ts){
    static char timestamp_string_buf[256];

    sprintf(timestamp_string_buf, "%d.%06d", (int) ts.tv_sec,
            (int) ts.tv_usec);

    return timestamp_string_buf;
}
*/