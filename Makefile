
LDFLAGS=-lrt -lpcap -pthread
CPPFLAGS=-Wall -g

all: rx tx_single tx_alternate tx_duplicate rx_status rx_alive_test



%.o: %.c
	gcc -c -o $@ $< $(CPPFLAGS)


rx: rx.o lib.o radiotap.o fec.o
	gcc -o $@ $^ $(LDFLAGS)

tx_single: tx_single.o lib.o fec.o
	gcc -o $@ $^ $(LDFLAGS)

tx_alternate: tx_alternate.o lib.o fec.o
	gcc -o $@ $^ $(LDFLAGS)

tx_duplicate: tx_duplicate.o lib.o fec.o
	gcc -o $@ $^ $(LDFLAGS)

rx_status: rx_status.o
	gcc -o $@ $^ $(LDFLAGS)

rx_alive_test: rx_alive_test.o
	gcc -o $@ $^ $(LDFLAGS)


clean:
	rm -f rx tx_single tx_alternate tx_duplicate rx_status rx_alive_test *~ *.o
