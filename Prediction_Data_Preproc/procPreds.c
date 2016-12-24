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

// TODO: Split each line using strtok() and store the tokens into an array (http://stackoverflow.com/a/15472429 and http://stackoverflow.com/a/15472359)

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
 * param flows: Array of testing set flows.
 * param numFlows: Number of flows in the array.
 * return: 1 if successful, 0 otherwise.
 */
int procFlowPred(char *inputCSV, char *outputCSV, Flow **flows, int numFlows){
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
	
	/* Loop through and process each line in the input CSV file. */
	int i;
	int goes = 0;
	char *p;
	char *items[LINE_ITEMS];
	while ((read = getline(&line, &bufLen, f)) != -1) {
		/* Parse the comma-separated line into an array. */
		p = strtok(line, ",");
		i = 0;
		while (p != NULL){
			items[i++] = p;
			p = strtok(NULL, ",");
		}
		
		/* TODO: Find the matching flow for this packet and record the */
		/* 		 predicted value into the struct. */

		/* For testing: stop early! */
		if (goes > 3)
			break;
		++goes;
	}

	free(line);
	
	return 1;
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