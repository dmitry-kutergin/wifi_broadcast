//   2017 dkutergin

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/epoll.h>
#include <time.h>
#include <pthread.h>


#include "lib.h"


void lib_init_packet_buffer(packet_buffer_t *p) {
	assert(p != NULL);

	p->valid = 0;
	p->crc_correct = 0;
	p->tx_done = 0;
	p->len = 0;
	p->data = NULL;
}

void lib_alloc_packet_buffer(packet_buffer_t *p, size_t len) {
	assert(p != NULL);
	assert(len > 0);

	p->len = 0;
	p->data = (uint8_t*)malloc(len);
}

void lib_free_packet_buffer(packet_buffer_t *p) {
	assert(p != NULL);

	free(p->data);
	p->len = 0;
}

packet_buffer_t *lib_alloc_packet_buffer_list(size_t num_packets, size_t packet_length) {
	packet_buffer_t *retval;
	int i;

	assert(num_packets > 0 && packet_length > 0);

	retval = (packet_buffer_t *)malloc(sizeof(packet_buffer_t) * num_packets);
	assert(retval != NULL);

	for(i=0; i<num_packets; ++i) {
		lib_init_packet_buffer(retval + i);
		if(packet_length)
			lib_alloc_packet_buffer(retval + i, packet_length);
	}

	return retval;
}

void lib_free_packet_buffer_list(packet_buffer_t *p, size_t num_packets) {
	int i;

	assert(p != NULL && num_packets > 0);

	for(i=0; i<num_packets; ++i) {
		lib_free_packet_buffer(p+i);
	}

	free(p);
}

void gc_pcap(int status, void * arg)
{
    if (arg)
        pcap_close((pcap_t *) arg);
    printf("%s\n", __PRETTY_FUNCTION__);
}

//pthread attributes garbage collector
void gc_pattr(int status, void * arg)
{
    if (arg) {
        pthread_attr_t * pa = (pthread_attr_t *) arg;
        pthread_attr_destroy(pa);
    }
    printf("%s\n", __PRETTY_FUNCTION__);
}
//pthread pointers garbage collector
void gc_pthr(int status, void * arg)
{
    if (arg) {
        pthread_t * pthr = (pthread_t *) arg;
        pthread_cancel(*pthr);
        pthread_join(*pthr, NULL);
    }
    printf("%s\n", __PRETTY_FUNCTION__);
}
//EPoll file descriptor garbage collector
void gc_epoll(int status, void * arg)
{
    if (arg) {
        int epfd = *(int *) arg;
        close(epfd);
    }
    printf("%s\n", __PRETTY_FUNCTION__);
}

//timer handle garbage collector
void gc_timer(int status, void * arg)
{
    if (arg) {
        timer_t * tp_timer = (timer_t *) arg;
        timer_delete(*tp_timer);
    }
    printf("%s\n", __PRETTY_FUNCTION__);
}
//shared memory garbage collector
void gc_shm(int status, void * arg)
{
    if (arg) {
        char * name = (char *) arg;
        shm_unlink(name);
    }
    printf("%s\n", __PRETTY_FUNCTION__);
}





