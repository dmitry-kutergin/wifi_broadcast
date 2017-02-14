
LDFLAGS=-lrt -lpcap -pthread
CPPFLAGS=-Wall -g

all: rx tx rx_status rx_alive_test



%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)


rx: rx.o lib.o radiotap.o fec.o
	gcc -o $@ $^ $(LDFLAGS)

tx: tx.o lib.o fec.o
	gcc -o $@ $^ $(LDFLAGS)

rx_status: rx_status.o
	gcc -o $@ $^ $(LDFLAGS)

rx_alive_test: rx_alive_test.o
	gcc -o $@ $^ $(LDFLAGS)


clean:
	rm -f rx tx rx_status rx_alive_test *~ *.o
