#***************************************************************************
#
#	Copyright (c) 1997-2022 Jeffrey Vernon Merkey
#	All Rights Reserved.
#
#**************************************************************************

INCLUDES=cworthy.h netware-screensaver.h 
UTILFILES=libcworthy.a sysmon 

# user utility build flags
U_CC = gcc
U_CCP = g++
U_CFLAGSP = -g -O3
U_CFLAGS_LIBP = -g -c -O3 
LD = ld
AR = ar
VERSION=1.3
BIN = /usr/bin

ifdef BINDIR
BIN = $(BINDIR)
endif

all : utilities

libcworthy.a: cworthy.o netware-screensaver.o
	$(AR) r libcworthy.a cworthy.o netware-screensaver.o 

cworthy.o: cworthy.c $(INCLUDES)
	$(U_CCP) $(U_CFLAGS_LIBP) -fPIC -Wall cworthy.c 

netware-screensaver.o: netware-screensaver.c $(INCLUDES)
	$(U_CCP) $(U_CFLAGS_LIBP) -fPIC -Wall netware-screensaver.c 

sysmon: sysmon.c libcworthy.a $(INCLUDES)
	$(U_CCP) $(U_CFLAGSP) sysmon.c libcworthy.a -Wall -o sysmon -lncursesw -lpthread -lrt -lz -lm -ldl -lssl -lcrypto 

clean:
	rm -rf *.o $(UTILFILES)

utilities: $(UTILFILES)

install: utilities
	install -m 0755 sysmon $(DESTDIR)$(BIN)

uninstall: 
	rm -vf $(DESTDIR)$(BIN)/sysmon


