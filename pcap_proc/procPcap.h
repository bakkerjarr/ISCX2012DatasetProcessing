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
* FILENAME : procPcap.h
*
* DESCRIPTION :
*       .h file for procPcap.c.
* 
* AUTHOR :  Jarrod N. Bakker    START DATE :    26/10/2016
*
**/
#ifndef PROCPCAP_H
#define PROCPCAP_H

int filterPcap(char * input_pcap, xmlDoc *doc, char* ouput_pcap);

#endif