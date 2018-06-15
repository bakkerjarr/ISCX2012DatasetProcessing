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
*           $ iscxFilter <XML file> <input PCAP> <output PCAP>
* 
* AUTHOR :  Jarrod N. Bakker 	START DATE :    25/10/2016
*
**/

#include "commonUtil.h"
#include "parseXML.h"
#include "procPcap.h"

static const char *ARGS = "<XML file> <input PCAP>";
static const int NUM_ARGS = 2; // No. of extra args passed to the program

int main (int argc, char * argv[]){
    
    /* Check command-line arugments. */
    if (argc != NUM_ARGS+1){
        fprintf(stderr, "Exiting: Expected %d arguments, passed %d.\n", NUM_ARGS+1, argc);
        fprintf(stdout, "Usage: %s %s\n", argv[0], ARGS);
        return 1;
    }
    
    char *xml_filename = argv[1];
    xmlDoc *doc;
        
    doc = parseXML(xml_filename);
    //printXML(doc);
    
    // TODO: Process the PCAP file.
    char *input_pcap = argv[2];
    char *output_pcap = "NOTHING!\0";
    
    if (!filterPcap(input_pcap, doc, output_pcap)){
       fprintf(stderr, "Exiting: PCAP filtering failed.\n");
       xmlFreeDoc(doc);
       return 1;
    }
        
    xmlFreeDoc(doc);
    return 0;
}