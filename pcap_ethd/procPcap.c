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
* AUTHOR :  Jarrod N. Bakker    START DATE :    2/11/2016
*
**/

#include <pcap.h>
#include <stdio.h>
#include "procPcap.h"
/* Directives for handling packets. */
#include <arpa/inet.h> // Byte order conversion functions
#include <netinet/if_ether.h> // The Ethernet frame header

static void processPkt(const unsigned char *rawPkt, const struct pcap_pkthdr rawHdr, const char *newMAC);
static const char *timestamp_string(struct timeval ts);

//static 

/**
 * Changes the destination MAC address of packets within the PCAP
 * file 'inputPCAP' to 'newMAC' if the original is not the broadcast
 * MAC address. The modified packets are writen to the new PCAP file
 * 'outputPCAP'.
 * 
 * param inputPCAP: Path of the input PCAP file.
 * param newMAC: MAC address to write in.
 * param outputPCAP: Path of the new PCAP file.
 * return: 1 if successful, 0 otherwise.
 */
int ppEthDst(char *inputPCAP, const char *newMAC, char *ouputPCAP){
    char errbuf[PCAP_ERRBUF_SIZE];
    fprintf(stdout,"Opening PCAP data using file: %s\n", inputPCAP);
    pcap_t *pcap = pcap_open_offline(inputPCAP, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "ERROR: PCAP error: %s\n", errbuf);
        return 0;
    }
    
    const unsigned char *pkt;
    struct pcap_pkthdr header;
    int i = 0;
    while ((pkt = pcap_next(pcap, &header)) != NULL) {
        fprintf(stdout, "Packet timestamp: %s\n", timestamp_string(header.ts));
        i++;
        if (i == 9)
           break;
        processPkt(pkt, header, newMAC);
        // TODO: Write it to the new PCAP file.
    }
    
    return 1;   
}

/**
 * Replace the destination MAC address of a packet with newMAC if 
 * the current destination MAC address is no the broadcast MAC address.
 * 
 * Assumes that the packet uses Ethernet encapsulation.
 * 
 * param rawPkt: The packet to process.
 * param rawHdr: PCAP header of the packet.
 * param newMAC: MAC to overwrite with.
 */
static void processPkt(const unsigned char *rawPkt, 
                      const struct pcap_pkthdr rawHdr, const char *newMAC){
    const unsigned char *pkt = rawPkt;
    struct pcap_pkthdr hdr = rawHdr;
    /* The packet should be larger than the Ethernet header. */
    if (hdr.caplen < sizeof(struct ether_header)){
        return;
    }    
    const struct ether_header *eth = (struct ether_header*) pkt;
    /* Replace the destination MAC address if needed */
    if (eth->ether_dhost);
    // TODO: How to best check the MAC address? Compare with a hex variable? What is the byte ordering of MAC addresses?
}

/**
 * This function has been adapted from: 
 * http://inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c
 * 
 * Note: this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
static const char *timestamp_string(struct timeval ts){
    static char timestamp_string_buf[256];
    sprintf(timestamp_string_buf, "%d.%06d", (int) ts.tv_sec,
            (int) ts.tv_usec);
    return timestamp_string_buf;
}
