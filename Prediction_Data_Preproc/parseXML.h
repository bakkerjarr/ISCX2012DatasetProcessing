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
* FILENAME : parseXML.h
*
* DESCRIPTION :
*       .h file for parseXML.c.
* 
* AUTHOR :  Jarrod N. Bakker 	START DATE :    21/12/2016
*
**/
#ifndef PARSEXML_H
#define PARSEXML_H

/* XML attribute tag names */
#define IP_SRC "source"
#define IP_DST "destination"
#define TP_PROTO "protocolName"
#define PORT_SRC "sourcePort"
#define PORT_DST "destinationPort"
#define TAG "Tag"
#define TIME_START "startDateTime"
#define TIME_STOP "stopDateTime"

/* XML values for the protocolName attribute */
#define ICMP "icmp_ip"
#define TCP "tcp_ip"
#define UDP "udp_ip"

/* XML values for the Tag attribute */
#define TAG_ATTACK "Attack"
#define TAG_NORMAL "Normal"
/* An extra tag value for processing purposes */
#define TAG_NOTHING "Nothing"

#include <glib.h>

#include "procPreds.h"

void freeFlows(GHashTable *flows);
GHashTable * parseXML(char *filename, int * numFlows);
char * predictable_5tuple(char *ipSrc, char *ipDst, char *proto, int tpSrc, int tpDst);

#endif