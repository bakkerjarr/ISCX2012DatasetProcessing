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
* FILENAME : procPreds.h
*
* DESCRIPTION :
*       .h file for procPreds.c.
* 
* AUTHOR :  Jarrod N. Bakker 	START DATE :    22/12/2016
*
**/
#ifndef PROCPREDS_H
#define PROCPREDS_H
         
/* A struct that identifies the actual class (Tag) for a flow. */
typedef struct {
    char source[16];
    char destination[16];
    char protocolName[6];
    int sourcePort;
    int destinationPort;
    int startTimeStamp;
    int stopTimeStamp;
    char actualTag[7];
    char predictedTag[8]; 
} Flow;

Flow * procNewFlow();
int procFlowPred(char *inputCSV, char *outputCSV, Flow **flows, int numFlows);
void printFlow(Flow * flow);

#endif