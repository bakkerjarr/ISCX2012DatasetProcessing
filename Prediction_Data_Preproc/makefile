# Copyright 2016 Jarrod N. Bakker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Makefile for the datapp program. This program preprocesses raw data from
# experiements to extract the predicted classes for flows of traffic.
#
# Author: Jarrod N. Bakker
# Date: 21/12/2016
#

# Define variables for compilation
CC = gcc
CFLAGS = -Wall $(shell xml2-config --cflags)
LIBS = $(shell xml2-config --libs)
#DEPS = parseXML.h
SRC = datapp.c parseXML.c procPreds.c
OBJ = $(SRC:.c=.o)
OUT = datapp

all: $(OUT)

$(OUT): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<
   
clean:
	rm -f $(OUT) *.o
	
clean-prog:
	rm -f $(OUT)

clean-o:
	rm -f *.o