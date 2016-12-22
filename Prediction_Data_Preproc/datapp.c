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
* FILENAME : datapp.c
*
* DESCRIPTION :
*       Main file for the datapp program. This program preprocesses raw
*       data from experiements to extract the predicted classes for flows
*       of traffic.
*
*       Usage of the resulting program is as follows:
*           $ datapp <XML testing set file> <input predicted CSV> <output result CSV>
* 
* AUTHOR :  Jarrod N. Bakker 	START DATE :    21/12/2016
*
**/

#include <stdio.h>

#include "parseXML.h"

static const char *ARGS = "<XML testing set file> <input predicted CSV> <output result CSV>";
static const int NUM_ARGS = 1; // No. of extra args that are expected

int main (int argc, char * argv[]){
    
    /* Check command-line arugments. */
    if (argc != NUM_ARGS+1){
        fprintf(stderr, "Exiting: Expected %d arguments, passed %d.\n", NUM_ARGS, argc-1);
        fprintf(stdout, "Usage: %s %s\n", argv[0], ARGS);
        return 1;
    }
    
    char *xml_filename = argv[1];
    
    int numFlows = 0;
    Flow ** flows = parseXML(xml_filename, &numFlows);
    
    // TODO: Process the predicted flow values.
    char *input_csv = argv[2];
    char *output_csv = "NOTHING!\0";

    freeFlows(flows, numFlows);
    
    return 0;
}