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
* FILENAME : iscxFilter.c
*
* DESCRIPTION :
*       Main file for the ISCX 2012 DDoS PCAP file processing program.
*       XML files are provided as input describing what packets should be
*       selected from a PCAP file. The selected packets are then written
*       to a new PCAP file.
*
*       This file is responsible for setting up the environment for
*       parsing/writing packets to/from file and reading XML data.
*
*       Usage of the resulting program is as follows:
*           $ iscxFilter <MAC address> <input PCAP> <output PCAP>
* 
* AUTHOR :  Jarrod N. Bakker 	START DATE :    25/10/2016
*
**/

#include <ctype.h>
#include <netinet/ether.h> // Functions for converting MAC addresses
#include <stdio.h>
#include "procPcap.h"

static const char *ARGS = "<MAC address> <input PCAP> <output PCAP>";
static const int NUM_ARGS = 3; // No. of extra args passed to the program

int main (int argc, char * argv[]){
    
    /* Check command-line arugments. */
    if (argc != NUM_ARGS+1){
        fprintf(stderr, "Error: Expected %d arguments, passed %d.\n", NUM_ARGS, argc);
        fprintf(stdout, "Usage: %s %s\n", argv[0], ARGS);
        return 1;
    }
    
    struct ether_addr *macStruct = ether_aton(argv[1]);
    if (!macStruct){
        fprintf(stderr, "Error: %s is not a valid MAC address.\n", argv[1]);
        return 1;
    }
    unsigned char *mac = macStruct->ether_addr_octet;
    
    char *inputPCAP = argv[2];
    char *outputPCAP = "NOTHING!\0";
    
    if (!ppEthDst(inputPCAP, mac, outputPCAP)){
       fprintf(stderr, "Error: PCAP processing failed.\n");
       return 1;
    }
    
    fprintf(stdout, "PCAP processing complete.\n");
    return 0;
}