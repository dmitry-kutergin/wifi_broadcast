ifeq ($(MAKECMDGOALS), armhf)

CC:=arm-linux-gnueabihf-g++
TOOLS_PATH?=/home/dkutergin/rpi_host/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/
PATH+=:$(TOOLS_PATH)bin
INCLUDE:=-I$(TOOLS_PATH)lib \
-I./libpcap-dev/usr/include \
-I$(TOOLS_PATH)
LIBS:=-L$(TOOLS_PATH)arm-linux-gnueabihf/libc/lib/arm-linux-gnueabihf \
-L./libpcap-dev/usr/lib/arm-linux-gnueabihf
else
CC:=g++
INCLUDE:= 
LIBS:= 
endif
LDFLAGS=$(LIBS) -lrt -lpcap -pthread
CPPFLAGS=-Wall -g $(INCLUDE)

all: rx tx rx_status rx_alive_test
armhf: rx tx rx_status rx_alive_test


%.o: %.c
	$(CC) -c -o $@ $< $(CPPFLAGS)


rx: rx.o lib.o radiotap.o fec.o
	$(CC) -o $@ $^ $(LDFLAGS)

tx: tx.o lib.o fec.o
	$(CC) -o $@ $^ $(LDFLAGS)

rx_status: rx_status.o
	$(CC) -o $@ $^ $(LDFLAGS)

rx_alive_test: rx_alive_test.o
	$(CC) -o $@ $^ $(LDFLAGS)


clean:
	rm -f rx tx rx_status rx_alive_test *~ *.o

.PHOHY: all clean armhf