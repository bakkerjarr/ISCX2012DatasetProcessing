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
* FILENAME : procPreds.c
*
* DESCRIPTION :
*       This file loads in a CSV file to determines the predicted
*       classes for flows represented by a struct.
* 
* AUTHOR :  Jarrod N. Bakker 	START DATE :    222/12/2016
*
**/

#include <stdio.h>
#include <stdlib.h>
#include "parseXML.h"
#include "procPreds.h"

static const int LINE_ITEMS = 12;
static const double PCAP_TIME_START = 1276614067;

static int writeResults(char *outputCSV, GHashTable *flows);
static void iteratorWriteFlow(gpointer key, gpointer value, gpointer user_data);

/**
 * Create a new Flow struct and initialise required members.
 *
 * return: Pointer to a Flow struct.
 */
Flow * procNewFlow(){
    Flow * f = calloc(1, sizeof(Flow));
    if (f == NULL) {
        fprintf(stderr, "ERROR: malloc failed for new Flow struct.\n");
        exit(1);
    }
    strcpy(f->predictedTag, TAG_NOTHING);
    return f;
}

/**
 * Loop through the lines in a CSV file containing predictions on a
 * per-packet basis and determine the predicted class for each flow.
 * The results are written to a separate CSV file.
 *
 * Note: The predicted class for each flow is the late prediction for
 * each flow.
 *
 * param inputCSV: CSV file containing per-packet predictions.
 * param outputCSV: CSV file to write per-flow predictions to.
 * param flows: GHashTable of testing set flows.
 * param numFlows: Number of flows in the array.
 * return: 1 if successful, 0 otherwise.
 */
int procFlowPred(char *inputCSV, char *outputCSV, GHashTable *flows, int numFlows){
    FILE *f;
    char *line = NULL;
    size_t bufLen = 0;
    size_t read;
    
	/* Open the input CSV file. */
	f = fopen(inputCSV, "r");
    if (f == NULL) {
		fprintf(stderr, "ERROR: Unable to open input CSV file %s\n", inputCSV);
		return 0;
	}
	fprintf(stdout, "Processing input CSV file...\n");
    
	int i;
	int goes = 0;
	char *p;
	char *items[LINE_ITEMS];
	/* Determine the difference in time between the first flow 		*/
	/* summary and the first packet prediction. We will use this to */
	/* offset the predictions so that they may be matched with the  */
	/* appropriate flow summary. 									*/
	if ((read = getline(&line, &bufLen, f)) == -1){ // read in first line of CSV
		fprintf(stderr, "Failed to read the first line of the CSV file. "
						"Is the file empty?");
		return 0;
	}
	/* Parse the comma-separated line into an array. This will be */
	/* repeated for the first line but at little cost. */
	p = strtok(line, ",");
	i = 0;
	while (p != NULL){
		items[i++] = p;
		p = strtok(NULL, ",");
	}
	double capPcktStart = atof(items[i_PKT_TS]);
	double timeDiff = capPcktStart - PCAP_TIME_START;
	//printf("\nFirst PCAP packet:\t%.2f\nPacket capture:\t%.2f\nTime diff:\t%.2f\n\n", PCAP_TIME_START, capPcktStart, timeDiff);
    
	/* Loop through and process each line in the input CSV file. */
	do {
		/* Parse the comma-separated line into an array. */
		p = strtok(line, ",");
		i = 0;
		while (p != NULL){
			items[i++] = p;
			p = strtok(NULL, ",");
		}

		/* Offset the packet timestamp value. We'll use this variable */
		/* in order to avoid multiple conversions from a String to a */
		/* double.*/
		double pktTS = atof(items[i_PKT_TS]) - timeDiff;

		/*int qw;
		for (qw = 0; qw < LINE_ITEMS; ++qw)
			if (qw == i_PKT_TS)
				printf("%.2f |", pktTS);
			else
				printf("%s | ",items[qw]);
		printf("\n");*/
		
		/* Find the matching flow for this packet and copy the */
		/* predicted value into the struct. */
        char *key = predictable_5tuple(items[i_IPA], items[i_IPB],
                                       items[i_PROTO], items[i_TPA],
                                       items[i_TPB]);
        /* Skip this packet if it is not within the GHashTable. */
        if (!g_hash_table_contains(flows, key))
            continue;
        /* Fetch the flows that match the key. */
        GSList *flowList = NULL, *iterator = NULL;
        flowList = g_hash_table_lookup(flows, key);
        /* Loop through the GSList of flows and find one that matches */
        /* the time period of the packet. */
        Flow *curFlow;
        for(iterator = flowList; iterator; iterator->next){
             curFlow = iterator->data;
            /* Check if the packet timestamp is within the range of */
            /* the start and stop times (inclusive) of the current flow. */
            if (curFlow->startTimeStamp <= pktTS && pktTS <= curFlow->stopTimeStamp)
                stpcpy(curFlow->predictedTag, items[i_PRED]);
        }
        
		/* For testing: stop early! */
		//if (goes > 3)
		//	break;
		++goes;
	} while ((read = getline(&line, &bufLen, f)) != -1);

	free(line);
	fclose(f);
	
	fprintf(stdout, "Processing complete.\n");
	return writeResults(outputCSV, flows);
}

/**
 * Print the contents of a Flow struct to stdout.
 *
 * param flow: The Flow struct to print out.
 */
void printFlow(Flow * flow){
    fprintf(stdout, "Flow:\n");
    fprintf(stdout, "\tsource: %s\n", flow->source);
    fprintf(stdout, "\tdestination: %s\n", flow->destination);
    fprintf(stdout, "\tprotocolName: %s\n", flow->protocolName);
    fprintf(stdout, "\tsourcePort: %d\n", flow->sourcePort);
    fprintf(stdout, "\tdestinationPort: %d\n", flow->destinationPort);
    fprintf(stdout, "\tstartTimeStamp: %d\n", flow->startTimeStamp);
    fprintf(stdout, "\tstopTimeStamp: %d\n", flow->stopTimeStamp);
    fprintf(stdout, "\tactualTag: %s\n", flow->actualTag);
    fprintf(stdout, "\tpredictedTag: %s\n", flow->predictedTag);
}

/**
 * Serialise the flow structs and write into a new CSV file.
 * 
 * param outputCSV: CSV file to write per-flow predictions to.
 * param flows: GHashTable of testing set flows.
 * return: 1 if successful, 0 otherwise.
 */
static int writeResults(char *outputCSV, GHashTable *flows){
	/* Create the output CSV file. */
	FILE *f;
	fprintf(stdout, "Opening file for writing results: %s\n", outputCSV);
	f = fopen(outputCSV, "w");
    if (f == NULL) {
		fprintf(stderr, "ERROR: Unable to open output CSV file %s\n", outputCSV);
		return 0;
	}    
	g_hash_table_foreach(flows, (GHFunc)iteratorWriteFlow, f);
	fclose(f);	
	fprintf(stdout, "Writing complete.\n");
	return 1;
}
int iTest = 0;
/**
 * Write the flows within a GSList (value) to a file (user_data).
 */
static void iteratorWriteFlow(gpointer key, gpointer value, gpointer user_data){
    GSList *iterator = NULL;
    Flow *curFlow;
    for(iterator = value; iterator; iterator = iterator->next){
        curFlow = iterator->data;
        fprintf(user_data, "%s,%s,%s,%d,%d,%d,%d,%s,%s\n", 
            curFlow->source, curFlow->destination,
            curFlow->protocolName, curFlow->sourcePort,
            curFlow->destinationPort, curFlow->startTimeStamp,
            curFlow->stopTimeStamp, curFlow->actualTag,
            curFlow->predictedTag);
    }
}