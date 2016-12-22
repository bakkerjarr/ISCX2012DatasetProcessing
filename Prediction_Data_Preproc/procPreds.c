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
#include "procPreds.h"

/**
 * Create a new Flow struct and initialise required members.
 *
 * return: Pointer to a Flow struct.
 */
Flow * procNewFlow(){
    Flow * f = malloc(sizeof(Flow));
    memset(f, 0, sizeof(Flow));
    if (f == NULL) {
        fprintf(stderr, "ERROR: malloc failed for new Flow struct.\n");
        exit(1);
    }
    f->predictedTag = Nothing;
    return f;
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
    fprintf(stdout, "\tactualTag: %d\n", flow->actualTag);
    fprintf(stdout, "\tpredictedTag: %d\n", flow->predictedTag);
}