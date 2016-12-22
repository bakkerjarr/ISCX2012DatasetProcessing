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
* FILENAME : parseXML.c
*
* DESCRIPTION :
*       This file parses XML data from a file into data structures.
* 
* AUTHOR :  Jarrod N. Bakker 	START DATE :    21/12/2016
*
**/

#include <libxml/parser.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "parseXML.h"

static const char *XML_ENCODING = "UTF-8";

static int cleanDoc(xmlDoc *doc);
static void printXML(xmlDoc *doc);
static Flow ** extractFlows(xmlDoc *doc, int numFlows);

/**
 * Parse an XML file.
 * 
 * param filename: String representing the path of the XML file.
 * param numFlows: Used to store the number of flows that are read in.
 * return: xmlDoc representing the loaded XML file.
 */
Flow ** parseXML(char *filename, int * numFlows){
    xmlDoc *doc;
    fprintf(stdout,"Reading XML data from file: %s\n", filename);
    doc = xmlReadFile(filename, XML_ENCODING, 0);
    *numFlows = cleanDoc(doc);
    Flow **flows = extractFlows(doc, *numFlows);    
    xmlFreeDoc(doc);
    return flows;
}

/**
 * Free the contents of the array of Flow structs.
 *
 * param flows: Array of pointer to Flow structs.
 */
void freeFlows(Flow **flows, int numFlows){
    fprintf(stdout, "Cleaning up flow array... ");
    int i;
    for (i = 0; i < numFlows; ++i){
        free(flows[i]);
    }
    free(flows);
    fprintf(stdout, "COMPLETE!\n");
}

/**
 * Print the contents within a xmlDoc to stdout.
 * 
 * param doc: xmlDoc to print.
 */
static void printXML(xmlDoc *doc){
    xmlNode *root, *firstChild, *node, *firstGchild, *gchNode;
    
    root = xmlDocGetRootElement(doc);
    firstChild = root->children;
    int i = 0;
    
    fprintf(stdout, "Root is <%s>\n", root->name);
    for (node = firstChild; node; node = node->next) {
        fprintf(stdout, "\tChild is <%s>\n", node->name);
        i++;
        firstGchild = node -> children;
        for (gchNode = firstGchild; gchNode; gchNode = gchNode->next){
            xmlChar * key = xmlNodeListGetString(doc, gchNode->xmlChildrenNode, 1);
            fprintf(stdout, "\t\tGrandchild is <%s>: %s\n", gchNode->name, key);
            xmlFree(key);
        }
        break;
    }
    fprintf(stdout, "COMPLETED. There are %d children.\n", i);
}

/**
 * Given a xmlDoc, iterate over the children and grandchilren nodes of
 * the root element and remove nodes that are <text> nodes.
 * 
 * param doc: xmlDoc to clean.
 * return: Number of elements now under the root element.
 */
static int cleanDoc(xmlDoc *doc){
    xmlNode *root, *firstChild, *node, *nextNode, *firstGchild,
                *gchNode, *nextGchNode;
    
    root = xmlDocGetRootElement(doc);
    firstChild = root->children;

    int num = 0;
    
    for (node = firstChild; node; node = nextNode) {
        nextNode = node->next;
        if (node->type == XML_TEXT_NODE){
            xmlUnlinkNode(node);
            xmlFreeNode(node);
        } else {
            firstGchild = node -> children;
            for (gchNode = firstGchild; gchNode; gchNode = nextGchNode){
                nextGchNode = gchNode -> next;
                if (gchNode->type == XML_TEXT_NODE){
                    xmlUnlinkNode(gchNode);
                    xmlFreeNode(gchNode);
                }
            }
        ++num;
        }
    }
    return num;
}

/**
 * Given an XML document, extract desired flow information into an
 * array of struct.
 *
 * param doc: xmlDoc containing flow data.
 * param numFlows: The number of flows that are being processed.
 * return: Pointer to an array of Flow structs.
 */
static Flow ** extractFlows(xmlDoc *doc, int numFlows){
    Flow **flows = calloc(numFlows, sizeof(Flow*));
    Flow *newFlow;
    xmlNode *root, *firstChild, *node, *firstGchild, *gchNode;
    
    root = xmlDocGetRootElement(doc);
    firstChild = root->children;
    
    int i = 0;
    for (node = firstChild; node; node = node->next) {
        firstGchild = node -> children;
        newFlow = procNewFlow();
        for (gchNode = firstGchild; gchNode; gchNode = gchNode->next){
            xmlChar * key = xmlNodeListGetString(doc, gchNode->xmlChildrenNode, 1);
            if(!strcmp(gchNode->name, IP_SRC))
                strcpy(newFlow->source, key);
            else if(!strcmp(gchNode->name, IP_DST))
                strcpy(newFlow->destination, key);
            else if(!strcmp(gchNode->name, TP_PROTO)){
                /* Modify the transport string if it necessary. */
                if (!strcmp(key, ICMP))
                    strcpy(newFlow->protocolName, "icmp");
                else if (!strcmp(key, TCP))
                    strcpy(newFlow->protocolName, "tcp");
                else if (!strcmp(key, UDP))
                    strcpy(newFlow->protocolName, "udp");
                else
                    strcpy(newFlow->protocolName, key);
            } else if(!strcmp(gchNode->name, PORT_SRC))
                newFlow->sourcePort = strtol(key, NULL, 10);
            else if(!strcmp(gchNode->name, PORT_DST))
                newFlow->destinationPort = strtol(key, NULL, 10);
            else if(!strcmp(gchNode->name, TIME_START)){
                struct tm t;
                strptime(key, "%Y-%m-%dT%H:%M:%S", &t);
                newFlow->startTimeStamp = mktime(&t);
            } else if(!strcmp(gchNode->name, TIME_STOP)){
                struct tm t;
                strptime(key, "%Y-%m-%dT%H:%M:%S", &t);
                newFlow->stopTimeStamp = mktime(&t);
            } else if (!strcmp(gchNode->name, TAG)){
                if (!strcmp(key, TAG_NORMAL))
                    newFlow->actualTag = Normal;
                else
                    newFlow->actualTag = Attack;
            } else;
            xmlFree(key);
        }
        flows[i] = newFlow;
        ++i;
    }
    return flows;
}