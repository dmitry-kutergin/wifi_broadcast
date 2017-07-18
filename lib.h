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
#pragma once



#include <stdint.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <ctype.h>

#include "wifibroadcast.h"

typedef struct {
	uint32_t received_packet_cnt;
	uint32_t wrong_crc_cnt;
	int8_t current_signal_dbm;
} wifi_adapter_rx_status_t;

typedef struct {
	time_t last_update;
	uint32_t received_block_cnt;
	uint32_t damaged_block_cnt;
	uint32_t tx_restart_cnt;

	uint32_t wifi_adapter_cnt;
	wifi_adapter_rx_status_t adapter[MAX_PENUMBRA_INTERFACES];
} wifibroadcast_rx_status_t;

typedef struct {
	uint8_t valid;
	uint8_t crc_correct;
	uint16_t * shadow_tx_done;
	uint8_t tx_done;
	size_t len; //this is the actual length of the packet stored in data
	uint8_t *data;
} packet_buffer_t;


//this sits at the payload of the wifi packet (outside of FEC)
typedef struct {
    uint16_t block_number;
    uint8_t packet_number;
    uint8_t fec_taint;
} __attribute__((packed)) wifi_packet_header_t;

//this sits at the data payload (which is usually right after the wifi_packet_header_t) (inside of FEC)
typedef struct {
    uint16_t nominal_packet_length;
    uint8_t num_data_blocks;
    uint8_t num_fecs_blocks;
} __attribute__((packed)) payload_header_t;

#define MAX_PACKET_LENGTH 4192
//maximum length of transmission data payload
#define MAX_USER_PACKET_LENGTH       1450
//maximum number of packets per block when set from command line
#define MAX_DATA_OR_FEC_PACKETS_PER_BLOCK 32
//absolute maximum allocated packets per block FEC+data
#define MAX_PACKETS_PER_BLOCK 64

packet_buffer_t *lib_alloc_packet_buffer_list(size_t num_packets, size_t packet_length);
void lib_free_packet_buffer_list(packet_buffer_t *p, size_t num_packets);

void gc_pcap(int status, void * arg);
//pthread attributes garbage collector
void gc_pattr(int status, void * arg);

//pthread pointers garbage collector
void gc_pthr(int status, void * arg);

//EPoll file descriptor garbage collector
void gc_epoll(int status, void * arg);

//timer handle garbage collector
void gc_timer(int status, void * arg);

//shared memory garbage collector
void gc_shm(int status, void * arg);

//printing binary data in ASCII
void hexdump(void *mem, unsigned int len);

//Radiotap header TX flag addition
#define IEEE80211_RADIOTAP_F_TX_SEQ 0x0010

//linux kernel ieee80211.h header fragment
#define IEEE80211_FCTL_TODS 0x0100
#define IEEE80211_FTYPE_DATA 0x0008
#define IEEE80211_SCTL_SEQ 0xFFF0
#define IEEE80211_SCTL_FRAG 0x000F

struct ieee80211_hdr_3addr {
	__le16 frame_control;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctrl;
} __attribute__((packed)) __attribute__((aligned (2)));


#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)


