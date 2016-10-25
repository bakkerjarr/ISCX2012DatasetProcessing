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
* FILENAME : parseXML.c
*
* DESCRIPTION :
*       This file parses XML data from a file into data structures.
* 
* AUTHOR :  Jarrod N. Bakker 	START DATE :    25/10/2016
*
**/

#include "parseXML.h"

static const char *XML_ENCODING = "UTF-8";

static void cleanDoc(xmlDoc *doc);

/**
 * Parse an XML file.
 * 
 * param filename: String representing the path of the XML file.
 * return: xmlDoc representing the loaded XML file.
 */
xmlDoc * parseXML(char *filename){
    xmlDoc *doc;    
    doc = xmlReadFile(filename, XML_ENCODING, 0);
    cleanDoc(doc);
    return doc;
}

/**
 * Print the contents within a xmlDoc to stdout.
 * 
 * param doc: xmlDoc to print.
 */
void printXML(xmlDoc *doc){
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
    }
    fprintf(stdout, "COMPLETED. There are %d children.\n", i);
}

/**
 * Given a xmlDoc, iterate over the children and grandchilren nodes of
 * the root element and remove nodes that are <text> nodes.
 * 
 * param doc: xmlDoc to clean.
 */
static void cleanDoc(xmlDoc *doc){
    xmlNode *root, *firstChild, *node, *nextNode, *firstGchild,
                *gchNode, *nextGchNode;
    
    root = xmlDocGetRootElement(doc);
    firstChild = root->children;

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
        }
    }
}