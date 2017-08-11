// (c)2015 befinitiv
//    2017 dkutergin

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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include "radiotap/radiotap_iter.h"
#include <argp.h>

#include "fec.h"

#include "lib.h"
//#include "wifibroadcast.h"

//maximum injection rate in Mbytes/s
#define INJ_RATE_MAX (19000000 / 8) //Bytes/s
#define MIN_PACKET_LENGTH 256
#define WLAN_BUFFER_SIZE 64

#define FIFO_NAME "/tmp/fifo%d"
#define MAX_FIFOS 8
//number of overlay structures in circular buffer
#define OVERLAY_NUM 4
#define DEBUG 0

/* this is the template radiotap header we send packets out with */
#if 0
static u8 u8aRadiotapHeader[] = {0x00, 0x00,  // <-- radiotap version
    0x0c, 0x00,// <- radiotap header length
    0x04, 0x80, 0x00, 0x00,// <-- radiotap present flags
//	0x18, // datarate 12Mbit
//	0x24, // datarate 18Mbit
//	0x30, // datarate 24Mbit
//	0x48, // datarate 36Mbit
    0x60,// datarate 48Mbit
    0x0, 0x18, 0x00};

/* Penumbra IEEE80211 header */

//the last byte of the mac address is recycled as a port number
#define SRC_MAC_LASTBYTE 15
#define DST_MAC_LASTBYTE 21

static u8 u8aIeeeHeader[] = {0x08, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x13, 0x22, 0x33, 0x44, 0x55, 0x66, 0x13, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x10, 0x86};

#endif

struct tRadiotapHeader {
    struct ieee80211_radiotap_header radiotap_header;
    uint8_t DataRate;
    uint16_t TxFlags;
}__attribute__((packed));

//transmitting packet structure
struct pkt_struct_t {
    union {
        uint8_t bRadiotapHeader[sizeof(struct tRadiotapHeader)];
        struct tRadiotapHeader sRadiotapHeader;
    } RadiotapHeader;
    union {
        uint8_t bIeeeHeader[sizeof(struct ieee80211_hdr_3addr)];
        struct ieee80211_hdr_3addr sIeeeHeader;
    } IeeeHeader;
    wifi_packet_header_t wifi_hdr;
    payload_header_t payload_hdr;
    union {
        struct payload_t {
            uint16_t len;
            uint8_t dataBuff[MAX_USER_PACKET_LENGTH - sizeof(uint16_t)];
        } sPayload __attribute__((packed));
        uint8_t bPayload[sizeof(struct payload_t)];
    } payload;

}__attribute__((packed));

//size of all aux headers in transmitted packet
#define PACKET_OVERHEAD (sizeof(struct tRadiotapHeader) + sizeof(struct ieee80211_hdr_3addr) + sizeof(wifi_packet_header_t) + sizeof(payload_header_t))
#define PACKET_OVERHEAD_LEN (PACKET_OVERHEAD + sizeof(uint16_t))
//member of FIFO array
struct fifo_arr_t {
//	int seq_nr;
    //opened file descriptor for a FIFO
    int fd;
    //pointer to the active overlay for reception thread
    volatile unsigned int curr_rx_overlay;
    //pointer to the active overlay for processing thread
    volatile unsigned int curr_proc_overlay;
#ifdef BLOCK_TX
    //pointer to the active overlay for transmitting thread
    volatile unsigned int curr_tx_overlay;
#endif
    //overlay structure
    struct overlay_t {
        //variable packet payload size
        uint16_t packet_payload_length;
        //variable number of FEC packets
        int16_t fec_part_ratio;
        //variable number of DATA packets
        int16_t data_part_ratio;
        //index of the currently filled packet in the reception thread
        uint8_t curr_pb_data;
        //index of the currently filled packet in the reception thread
        //used in rate limiting, maximum value is transmitted and skipped packets combined
        uint8_t skip_pb_data;
#ifndef BLOCK_TX
        //index of the currently transmitted packet in the processing thread
        uint8_t tx_pb_data;
#endif
        //shared data medium for both FEC and DATA packets
        packet_buffer_t *pbl_placeholder;
        //pointer to the DATA portion of shared medium
        packet_buffer_t *pbl_data;
        //pointer to the FEC portion of shared medium
        packet_buffer_t *pbl_fec;
        //array of pointers to actual payload inside packet buffers in shared data medium
        unsigned char **data_blocks;
//		unsigned char **fec_blocks;
    } pb_overlay[OVERLAY_NUM];

};
//FIFO general structure
typedef struct {
    //number of active FIFOs
    unsigned int fifo_num;
#ifdef INTERLEAVED
    struct pkt_struct_t *interleaved_pkt;
    unsigned char interleaved;
#endif
    //FIFOs array
    struct fifo_arr_t * fifo_array;
    //packets retransmission count (obsolete)
    unsigned int transmission_count;
    //array of opened pcap handles for multipath transmission
    pcap_t **ppcap_arr;
    //number of active pcap devices (wlan cards) for multipath transmission
    unsigned char num_pcap;
    //selector between duplication or load sharing mode for multipath transmission
    unsigned char duplicated;
} fifo_t;

static fifo_t fifo;

static unsigned long int bytes_sent = 0;
struct timespec last_time = { 0 };

struct opts_t {
    int port;
    int fec_packets_per_block;
    size_t packet_length;
    int data_packets_per_block;
    size_t min_packet_length;
    int fifo_count;
    int transmission_count;
    uint64_t injection_rate;
    int frame_rate;
    int interleaved;
    int duplicated;
    char wlan_list[WLAN_BUFFER_SIZE];
};

//Version
const char *argp_program_version = "tx.1.0";
// Program documentation.
static char doc[] = "Raw data transmitter";
// Supported opts
static struct argp_option cmd_options[] =
        { { "port", 'p', "port", 0, "Port number 0-255 (default 0)" },
                { "block_packets", 'b', "count", 0,
                        "Number of data packets in a block (default 8). Needs to match with rx" },
                { "block_fec_packets", 'r', "count", 0,
                        "Number of FEC packets per block (default 4). Needs to match with rx" },
                { "packet_bytes", 'f', "bytes", 0,
                        "Number of bytes per packet (default 1450. max 1450). This is also the FEC block size. Needs to match with rx" },
                { "min_bytes", 'm', "bytes", 0,
                        "Minimum number of bytes per frame (default 0)" },
                { "stream", 's', "stream", 0,
                        "If <stream> is > 1 then the parameter changes \"tx\" input from stdin to named FIFOs. Each fifo transports a stream over a different port (starting at -p port and incrementing). FIFO names are \"/tmp/fifo%d\". (default 1)" },
                { "frequency", 'x', "value", 0,
                        "How often is a block transmitted (default 1)" }, {
                        "rate", 'i', "Mbps", 0, "Mbits/s transmission rate" },
                { "duplicate", 'd', 0, 0,
                        "Enable packet duplication through multiple interfaces, otherwise load sharing is performed" },
                { "fps", 'a', "fps", 0,
                        "Expected video FPS for optimal FEC/frame size calculation" },
#ifdef INTERLEAVED
                {   "interleaver", 't', 0, 0,
                    "Enable interleaver"},
#endif
                { "wlan", 'w', "list", 0, "WLAN list" }, { 0 } };

#if 0
//setting port number inside packet buffer
void set_port_no(uint8_t *pu, uint8_t port)
{
    //dirty hack: the last byte of the mac address is the port number. this makes it easy to filter out specific ports via wireshark
    //pu[sizeof(u8aRadiotapHeader) + SRC_MAC_LASTBYTE] = port;
    //pu[sizeof(u8aRadiotapHeader) + DST_MAC_LASTBYTE] = port;
    //setting port byte in MAC header field of MAC address last byte
    pu[SRC_MAC_LASTBYTE] = port;
    pu[DST_MAC_LASTBYTE] = port;
}

//putting default values to packet header structures
int packet_header_init(uint8_t *packet_header)
{
    u8 *pu8 = packet_header;
    //filling radio header buffer with default values
    memcpy(packet_header, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
    pu8 += sizeof(u8aRadiotapHeader);
    //filling IEEE header buffer with default values
    memcpy(pu8, u8aIeeeHeader, sizeof(u8aIeeeHeader));
    pu8 += sizeof(u8aIeeeHeader);

    //determine the length of the header
    return pu8 - packet_header;
}
packet_buffer_t * alloc_pb(int fec_packets_per_block)
{
    packet_buffer_t * fec_pb = lib_alloc_packet_buffer_list(
            fec_packets_per_block, sizeof(struct pkt_struct_t));
    int j;
    for (j = 0; j < fec_packets_per_block; ++j) {
        struct pkt_struct_t * ps = (struct pkt_struct_t *) fec_pb[j].data;
        memcpy(ps->RadiotapHeader, u8aRadiotapHeader,
                sizeof(u8aRadiotapHeader));
        memcpy(ps->IeeeHeader, u8aIeeeHeader, sizeof(u8aIeeeHeader));
    }
    return fec_pb;
}
#endif
//main internal data init function, allocates all necessary buffers and sets default values
void fifo_init(fifo_t *fifo, uint8_t fifo_count, uint8_t block_size_data,
               uint8_t block_size_fec, uint8_t port,
               uint16_t packet_payload_length, uint8_t inj_rate)
{
    int i;
    const uint8_t addr1[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const uint8_t addr2[] = { 0x02, 'w', 'i', 'f', 'i', 0 };
    const uint8_t addr3[] = { 0x22, 'w', 'i', 'f', 'i', 0 };

    //number of active FIFOs
    fifo->fifo_num = fifo_count;
    //allocation FIFO structures buffer
    fifo->fifo_array = (struct fifo_arr_t *) malloc(
            sizeof(struct fifo_arr_t) * fifo_count);
#ifdef INTERLEAVED
    fifo->interleaved_pkt = (struct pkt_struct_t *) malloc(
            (block_size_data + block_size_fec) * sizeof(struct pkt_struct_t));
    for (i = 0; i < (block_size_data + block_size_fec); ++i) {
        memcpy(fifo->interleaved_pkt[i].RadiotapHeader, u8aRadiotapHeader,
                sizeof(u8aRadiotapHeader));
        memcpy(fifo->interleaved_pkt[i].IeeeHeader, u8aIeeeHeader,
                sizeof(u8aIeeeHeader));
        set_port_no(fifo->interleaved_pkt[i].RadiotapHeader, i + port);
    }
#endif
    //setting 0 for active PCAP handles
    fifo->num_pcap = 0;
    //loop for allocating FIFO structure buffers and setting default values
    for (i = 0; i < fifo_count; ++i) {
//		fifo->fifo_array[i].seq_nr = 0;
        //FIFO file descriptor is set to 0
        fifo->fifo_array[i].fd = 0;
        //active overlay indexes are set to 0
        fifo->fifo_array[i].curr_proc_overlay = 0;
        fifo->fifo_array[i].curr_rx_overlay = 0;
#ifdef BLOCK_TX
        fifo->fifo_array[i].curr_tx_overlay = 0;
#endif

        int k;
        //filling overlay structures
        for (k = 0; k < OVERLAY_NUM; ++k) {
            //setting number of FEC packets per data transmission block
            fifo->fifo_array[i].pb_overlay[k].fec_part_ratio = block_size_fec;
            //setting number of DATA packets per data transmission block
            fifo->fifo_array[i].pb_overlay[k].data_part_ratio = block_size_data;
            //setting default transmission packet payload length
            fifo->fifo_array[i].pb_overlay[k].packet_payload_length =
                    packet_payload_length;
            //allocating memory for shared data medium for FEC+DATA buffers
            fifo->fifo_array[i].pb_overlay[k].pbl_placeholder =
                    lib_alloc_packet_buffer_list(MAX_PACKETS_PER_BLOCK,
                                                 sizeof(struct pkt_struct_t));
            //setting currently receiving buffer index in rx thread to 0
            fifo->fifo_array[i].pb_overlay[k].curr_pb_data = 0;
            fifo->fifo_array[i].pb_overlay[k].skip_pb_data = 0;
#ifndef BLOCK_TX
            //setting currently transmitting buffer index in processing thread to 0
            fifo->fifo_array[i].pb_overlay[k].tx_pb_data = 0;
#endif
            //initializing DATA packet buffer array pointer at the beginning of shared medium
            fifo->fifo_array[i].pb_overlay[k].pbl_data = fifo->fifo_array[i]
                    .pb_overlay[k].pbl_placeholder;
            //initializing FEC packet buffer array pointer right after DATA packet buffer array
            fifo->fifo_array[i].pb_overlay[k].pbl_fec = fifo->fifo_array[i]
                    .pb_overlay[k].pbl_placeholder + block_size_data;
            //allocating packet buffers payload pointers buffer
            fifo->fifo_array[i].pb_overlay[k].data_blocks =
                    (unsigned char **) malloc(
                    MAX_PACKETS_PER_BLOCK * sizeof(unsigned char *));
//			fifo->fifo_array[i].pb_overlay[k].fec_blocks =
//					(unsigned char **) malloc(
//							MAX_PACKETS_PER_BLOCK * sizeof(unsigned char *));

            //prepare the buffers with headers
            int j;
            for (j = 0; j < MAX_PACKETS_PER_BLOCK; ++j) {
                //setting buffer used data length to 0
                fifo->fifo_array[i].pb_overlay[k].pbl_placeholder[j].len = 0;
                struct pkt_struct_t * ps = (struct pkt_struct_t *) fifo
                        ->fifo_array[i].pb_overlay[k].pbl_placeholder[j].data;

                ps->RadiotapHeader.sRadiotapHeader.radiotap_header.it_version =
                        0;
                ps->RadiotapHeader.sRadiotapHeader.radiotap_header.it_pad = 0;
                ps->RadiotapHeader.sRadiotapHeader.radiotap_header.it_len =
                        sizeof(struct tRadiotapHeader);
                ps->RadiotapHeader.sRadiotapHeader.radiotap_header.it_present =
                        (1 << IEEE80211_RADIOTAP_TX_FLAGS)
                                | (1 << IEEE80211_RADIOTAP_RATE);
                ps->RadiotapHeader.sRadiotapHeader.DataRate = inj_rate * 2;
                ps->RadiotapHeader.sRadiotapHeader.TxFlags =
                        IEEE80211_RADIOTAP_F_TX_NOACK
                                | IEEE80211_RADIOTAP_F_TX_SEQ;

                //initializing radio tap header
                /*memcpy(ps->RadiotapHeader, u8aRadiotapHeader,
                 sizeof(u8aRadiotapHeader));*/
                //initializing IEEE header
//                memcpy(ps->IeeeHeader, u8aIeeeHeader, sizeof(u8aIeeeHeader));
                ps->IeeeHeader.sIeeeHeader.frame_control = IEEE80211_FCTL_TODS
                        | IEEE80211_FTYPE_DATA;
                ps->IeeeHeader.sIeeeHeader.duration_id = 0;

                memmove(ps->IeeeHeader.sIeeeHeader.addr1, addr1, ETH_ALEN);
                memmove(ps->IeeeHeader.sIeeeHeader.addr2, addr2, ETH_ALEN);
                memmove(ps->IeeeHeader.sIeeeHeader.addr3, addr3, ETH_ALEN);
                ps->IeeeHeader.sIeeeHeader.addr2[5] = i + port;
                ps->IeeeHeader.sIeeeHeader.addr3[5] = i + port;
                ps->IeeeHeader.sIeeeHeader.seq_ctrl = (IEEE80211_SCTL_SEQ
                        & (0x861 << 4)) | (IEEE80211_SCTL_FRAG & 0x0);

//                set_port_no(ps->RadiotapHeader, i + port);
                //assigning payload buffer pointers to packet structure payload portions
                fifo->fifo_array[i].pb_overlay[k].data_blocks[j] = ps->payload
                        .bPayload;
//				fifo->fifo_array[i].pb_overlay[k].fec_blocks[j] =
//										ps->payload;
            }

        }

    }

}

//FIFO structure garbage collector
void fifo_gc(fifo_t *fifo)
{
    unsigned int i;
#ifdef INTERLEAVED
    free(fifo->interleaved_pkt);
#endif
    //closing all opened PCAP handles
    for (i = 0; i < fifo->num_pcap; ++i) {
        if (fifo->ppcap_arr[i]) pcap_close(fifo->ppcap_arr[i]);
    }
    //freeing PCAP handles array
    free(fifo->ppcap_arr);
    fifo->num_pcap = 0;
    //deallocating all FIFOs array elements
    for (i = 0; i < fifo->fifo_num; ++i) {
        //closing file descriptor for opened FIFOs
        if (fifo->fifo_array[i].fd && fifo->fifo_array[i].fd != STDIN_FILENO) close(
                fifo->fifo_array[i].fd);
        //freeing overlay buffers
        int k;
        for (k = 0; k < OVERLAY_NUM; ++k) {

            lib_free_packet_buffer_list(
                    fifo->fifo_array[i].pb_overlay[k].pbl_placeholder,
                    MAX_PACKETS_PER_BLOCK);

            free(fifo->fifo_array[i].pb_overlay[k].data_blocks);
//			free(fifo->fifo_array[i].pb_overlay[k].fec_blocks);

        }
    }
    //freeing FIFOs array
    free(fifo->fifo_array);
}

//FIFO file descriptor garbage collector
void gc_fifo(int status, void * arg)
{
    fifo_t * fifo = (fifo_t *) arg;
    if (fifo) fifo_gc(fifo);
    fprintf(stderr, "%s\n", __PRETTY_FUNCTION__);
}
//open FIFOs for read
void fifo_open(fifo_t *fifo, int fifo_count)
{
    int i;
    if (fifo_count > 1) {
        //new FIFO style

        //first, create all required fifos
        for (i = 0; i < fifo_count; ++i) {
            char fn[256];
            sprintf(fn, FIFO_NAME, i);

            unlink(fn);
            if (mkfifo(fn, 0666) != 0) {
                fprintf(stderr, "Error creating FIFO \"%s\"\n", fn);
                exit(1);
            }
        }

        //second: wait for the data sources to connect
        for (i = 0; i < fifo_count; ++i) {
            char fn[256];
            sprintf(fn, FIFO_NAME, i);

            printf("Waiting for \"%s\" being opened from the data source... \n",
                   fn);
            if ((fifo->fifo_array[i].fd = open(fn, O_RDONLY)) < 0) {
                fprintf(stderr, "Error opening FIFO \"%s\"\n", fn);
                exit(1);
            }
            printf("OK\n");
        }
    } else {
        //old style STDIN input
        fifo->fifo_array[0].fd = STDIN_FILENO;
    }
}
//populating select file descriptor set
void fifo_create_select_set(fifo_t *fifo, int fifo_count, fd_set *fifo_set,
                            int *max_fifo_fd)
{
    int i;

    FD_ZERO(fifo_set);

    for (i = 0; i < fifo_count; ++i) {
        FD_SET(fifo->fifo_array[i].fd, fifo_set);

        if (fifo->fifo_array[i].fd > *max_fifo_fd) {
            *max_fifo_fd = fifo->fifo_array[i].fd;
        }
    }
}

//function that does actual packet transmission, t
void pb_transmit_packet(fifo_t * fifo, unsigned int curr_fifo_index,
                        uint8_t *data, uint16_t blknum, uint8_t is_fec)
{
    //struct fifo_arr_t * curr_fifo = &fifo->fifo_array[curr_fifo_index];
    struct pkt_struct_t * ps = (struct pkt_struct_t *) data;
    static unsigned char curr_ppcap = 0;
    static uint8_t pktnum = 0;
    static uint64_t pktnum_all = 0;
    static uint16_t blknum_old = 0;
#ifdef PKT_LOSS_EN
    static uint64_t skipped_pkt = 0;
#endif

//    printf("blknum %d, blknum_old %d, pktnum %d, is_fec %d\n", blknum, blknum_old, pktnum, is_fec);
    if (blknum != blknum_old) {
        pktnum = 0;
#ifdef PKT_LOSS_EN
        skipped_pkt = 0;
#endif
    }
    ps->wifi_hdr.block_number = blknum;
    ps->wifi_hdr.packet_number = pktnum++;
    ps->wifi_hdr.fec_taint = is_fec;

    blknum_old = blknum;

    //copy data
//    memcpy(packet_transmit_buffer + packet_header_len + sizeof(wifi_packet_header_t), packet_data, packet_payload_length);

//    int plen = packet_payload_length + packet_header_len + sizeof(wifi_packet_header_t);
    //calculating actual transmission size
    int plen = PACKET_OVERHEAD + ps->payload_hdr.nominal_packet_length;
    //cycling through all opened PCAP handles
    int i;
    for (i = 0; i < fifo->num_pcap; ++i) {
        //if packet duplication for multipath transmission is not selected, send only on one PCAP handle at a time
        if (!fifo->duplicated && (curr_ppcap != i)) continue;
#ifndef TEST_EN
        int r;
        //trying inject bytes into one of the WLAN adapter through the opened PCAP handle
        while ((r = pcap_inject(fifo->ppcap_arr[i], data, plen)) <= 0) {
            sched_yield();
        }
        if (r != plen) {
            pcap_perror(fifo->ppcap_arr[i], (char *)"Trouble injecting packet");
            //exit(1);
        }
#else

#ifdef HEX_DUMP
        printf(">>>>>>>Packet# %d, Block# %d, packet index %ld, nominal len %d, payload len %d\n",
               ps->wifi_hdr.packet_number, blknum, pktnum_all, plen, ps->payload.sPayload.len);
        if(is_fec)
        printf("FEC tx, len%d\n", plen);
        else
        printf("DATA tx, len%d\n", plen);
        hexdump(data, PACKET_OVERHEAD);
        hexdump(&ps->wifi_hdr, sizeof(ps->wifi_hdr));
        hexdump(data + PACKET_OVERHEAD, ps->payload_hdr.nominal_packet_length);
#else
#ifdef PKT_LOSS_EN
        if(!is_fec && (skipped_pkt < ps->payload_hdr.num_fecs_blocks)) {
            skipped_pkt++;
            continue;
        }
#endif
#ifdef ONE2ONE_OUT
        if(!is_fec)
        	write(STDOUT_FILENO, data + PACKET_OVERHEAD_LEN, ps->payload.sPayload.len);
#else
        write(STDOUT_FILENO, data, plen);
#endif
#endif

        if (!is_fec) pktnum_all++;

#endif
        //sent bytes counter for tx statistics
        bytes_sent += plen;
    }
    //adjusting active PCAP handle index
    curr_ppcap++;
    curr_ppcap %= fifo->num_pcap;
}

//void pb_transmit_block(packet_buffer_t *pbl, pcap_t *ppcap, int *seq_nr, int port,
//		int packet_payload_length, uint8_t *packet_transmit_buffer, int packet_header_len,
//		int data_packets_per_block, int fec_packets_per_block, int transmission_count) {

//data block process function. Adds FECs packets to the block
void pb_process_block(fifo_t * fifo, unsigned int curr_fifo_index,
                      uint16_t * blknum)
{
    struct fifo_arr_t * curr_fifo = &fifo->fifo_array[curr_fifo_index];
    int16_t i;
#ifndef BLOCK_TX
//    printf("pb_process_block tx_pb_data %d, curr_pb_data %d\n",
//    		curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].tx_pb_data, curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].curr_pb_data);
    //transmit remaining ready data packets if any
    while (curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].tx_pb_data
            < curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].curr_pb_data) {
//        printf("pb_process_block TX pkt blknum %d\n", blknum);
        pb_transmit_packet(
                fifo,
                curr_fifo_index,
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].pbl_data[curr_fifo
                        ->pb_overlay[curr_fifo->curr_proc_overlay].tx_pb_data++]
                        .data,
                *blknum, 0);
        //If we are rate limiting data_part ratio in a header is 1 and fec part ration is 0
        //which effectively means block size is 1, so we need to update blknum after each packet transfer
        if (curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].fec_part_ratio < 0)
                *blknum += 1;
    }
#endif
    //if number of FEC packets is greater than 0
    if (curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].fec_part_ratio > 0) {
        //encode FEC data
        fec_encode(
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay]
                        .packet_payload_length,
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].data_blocks,
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay]
                        .data_part_ratio,
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].data_blocks
                        + curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay]
                                .data_part_ratio,
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay]
                        .fec_part_ratio);
    }
#ifndef BLOCK_TX
    //transmit all FEC packets
    for (i = 0; i < curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay]
                            .fec_part_ratio; ++i) {
        packet_buffer_t *pb = &curr_fifo->pb_overlay[curr_fifo
                ->curr_proc_overlay].pbl_data[curr_fifo->pb_overlay[curr_fifo
                ->curr_proc_overlay].data_part_ratio + i];
        struct pkt_struct_t * ps = (struct pkt_struct_t *) pb->data;
        //filling packet header data
        //actual data length
//    	ps->payload.sPayload.len = curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].packet_payload_length;
        //current block packet length
        ps->payload_hdr.nominal_packet_length = curr_fifo->pb_overlay[curr_fifo
                ->curr_proc_overlay].packet_payload_length;
        //current FEC ratio
        ps->payload_hdr.num_data_blocks = curr_fifo->pb_overlay[curr_fifo
                ->curr_proc_overlay].data_part_ratio;
        //current DATA ratio
        ps->payload_hdr.num_fecs_blocks = curr_fifo->pb_overlay[curr_fifo
                ->curr_proc_overlay].fec_part_ratio;

        pb_transmit_packet(fifo, curr_fifo_index, pb->data, *blknum, 1);
    }
    curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].tx_pb_data = 0;
#endif
    //current packet index reset
    curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].curr_pb_data = 0;
    //reset the length back
    for (i = 0; i < curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay]
                            .data_part_ratio; ++i) {
        curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].pbl_data[i].len = 0;

    }
    //If it is not rate limiter case, update block number as usual
    if (curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].fec_part_ratio >= 0)
        *blknum += 1;
    //moving to ther next overlay to process
    curr_fifo->curr_proc_overlay = (curr_fifo->curr_proc_overlay + 1)
            % OVERLAY_NUM;


}
#ifdef BLOCK_TX
//function transmits a block of data
void pb_transmit_block(fifo_t * fifo, unsigned int curr_fifo_index) {
    struct fifo_arr_t * curr_fifo = &fifo->fifo_array[curr_fifo_index];
    static uint16_t blknum = 0;
    int x;

    //if retransmission count is more than 1 duplicating transmission of a block several times (obsolete, almost always a single transmission)
    for (x = 0; x < fifo->transmission_count; ++x) {
        //send data and FEC packets interleaved
        unsigned int di = 0;
        unsigned int fi = 0;
        unsigned int i = 0;
#ifdef INTERLEAVED
        unsigned int j = 0;
        if (fifo->interleaved) {
            unsigned int pi = 0;
            unsigned int k = 0, l = 0;
            struct pkt_struct_t * psd;
            struct pkt_struct_t * psf;
            while (di < curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].data_part_ratio || fi < curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].fec_part_ratio) {
                if (di < curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].data_part_ratio) {
                    for (j = 0; j < curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].data_part_ratio; j++) {
                        psd = (struct pkt_struct_t *) &curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].pbl_data[di].data;
                        *(uint32_t*) (fifo->interleaved_pkt[pi]->payload
                                + i) = *(uint32_t*) (psd->payload + k);
                        i += 4;
                        if (i > curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].nominal_packet_length) {
                            i = 0;
                            pb_transmit_packet(fifo, curr_fifo_index,
                                    (uint8_t *) &fifo->interleaved_pkt[pi]);
                            ++pi;
                        }
                        k += 4;
                        if (k > curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].nominal_packet_length) {
                            k = 0;
                            ++di;
                        }
                    }
                }
                if (fi < curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].fec_part_ratio) {
                    for (j = 0; j < curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].fec_part_ratio; j++) {
                        psf =
                        (struct pkt_struct_t *) &curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].pbl_fec[fi].data;
                        *(uint32_t*) (fifo->interleaved_pkt[pi]->payload
                                + i) = *(uint32_t*) (psf->payload + l);
                        i += 4;
                        if (i > curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].nominal_packet_length) {
                            i = 0;
                            pb_transmit_packet(fifo, curr_fifo_index,
                                    (uint8_t *) &fifo->interleaved_pkt[pi]);
                            ++pi;
                        }
                        j += 4;
                        if (j > curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].nominal_packet_length) {
                            j = 0;
                            ++fi;
                        }
                    }
                }
            }

        } else
#endif
        {
            //algorithm for even distribution of FEC and DATA packets inside the data block
            unsigned int fec_ratio = (curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].data_part_ratio
                    + curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].fec_part_ratio) /
            curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].fec_part_ratio;
            unsigned int data_ratio = (curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].data_part_ratio
                    + curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].fec_part_ratio) /
            curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].data_part_ratio;
            //going through FEC+DATA number of packets
            for (i = 1; i <= (curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].data_part_ratio + curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].fec_part_ratio);
                    ++i) {
                if ((i / fec_ratio) && (i / data_ratio)) {
                    if (fec_ratio > data_ratio) {
                        pb_transmit_packet(fifo, curr_fifo_index,
                                curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].pbl_fec[fi].data, blknum, 1);
                        fi++;
                    } else if (data_ratio > fec_ratio) {
                        pb_transmit_packet(fifo, curr_fifo_index,
                                curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].pbl_data[di].data, blknum, 0);
                        di++;
                    } else {
                        pb_transmit_packet(fifo, curr_fifo_index,
                                curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].pbl_fec[fi].data, blknum, 1);
                        fi++;
                        pb_transmit_packet(fifo, curr_fifo_index,
                                curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].pbl_data[di].data, blknum, 0);
                        di++;
                    }
                } else if (i / fec_ratio) {
                    pb_transmit_packet(fifo, curr_fifo_index,
                            curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].pbl_fec[fi].data, blknum, 1);
                    fi++;
                } else if (i / data_ratio) {
                    pb_transmit_packet(fifo, curr_fifo_index,
                            curr_fifo->pb_overlay[curr_fifo->curr_tx_overlay].pbl_data[di].data, blknum, 0);
                    di++;
                }

            }
        }
        blknum++;

    }

}
#endif
//signal handler for timer signal and all other signals
static void sig_handler(int signum)
{
    //printing tx statistics
    if ((signum == SIGALRM) || (signum == SIGWINCH)) {
        struct timespec now_time;
        clock_gettime(CLOCK_MONOTONIC, &now_time);
        fprintf(
        stderr,
                "---Data rate: %.3f KBits/s---\n"/*\033[1A"*/,
                ((float) bytes_sent * 8 / 1000)
                        / ((float) now_time.tv_sec
                                + (float) now_time.tv_nsec / 10e9
                                - (float) last_time.tv_sec
                                - (float) last_time.tv_nsec / 10e9));
        last_time = now_time;
        bytes_sent = 0;
    } else {
        //just invoking garbage collectors on any other signal than TIMER
        exit(0);
    }
}

//processing thread main function
static void * thread_proc(void *arg)
{
    fifo_t * pfifo = (fifo_t *) arg;
    unsigned int i;
    static uint16_t blknum = 0;
    while (1) {
        //cycling through all opened FIFOs
        for (i = 0; i < pfifo->fifo_num; ++i) {
            //thread cancellation point
            pthread_testcancel();
            uint8_t cpo_val = pfifo->fifo_array[i].curr_proc_overlay;
            //if processing thread overlay index reached reception thread overlay index move to the next FIFO
            if (pfifo->fifo_array[i].curr_rx_overlay
                    == cpo_val) {
#ifndef BLOCK_TX
//                printf("Tx from FIFO %d, curr_rx_overlay %d, curr_proc_overlay %d\n", i, pfifo->fifo_array[i].curr_rx_overlay, pfifo->fifo_array[i].curr_proc_overlay);
                //check if new data packets were read, if so transmit them immediately to reduce latency and tx burstiness (make more uniform transmission rate)

//                printf("tx_pb_data %d, curr_pb_data %d\n",
//                		pfifo->fifo_array[i].pb_overlay[cpo_val].tx_pb_data, pfifo->fifo_array[i].pb_overlay[cpo_val].curr_pb_data);
                while (pfifo->fifo_array[i].pb_overlay[cpo_val].tx_pb_data
                        < pfifo->fifo_array[i].pb_overlay[cpo_val].curr_pb_data) {
//                	printf("TX blknum %d\n", blknum);
                    pb_transmit_packet(
                            pfifo,
                            i,
                            pfifo->fifo_array[i].pb_overlay[cpo_val].pbl_data[pfifo
                                    ->fifo_array[i].pb_overlay[cpo_val]
                                    .tx_pb_data++].data,
                            blknum, 0);
                    //If we are rate limiting data_part ratio in a header is 1 and fec part ration is 0
                    //which effectively means block size is 1, so we need to update blknum after each packet transfer
                    if (pfifo->fifo_array[i].pb_overlay[cpo_val].fec_part_ratio < 0)
                        blknum++;

                }
#endif
                sched_yield();
                continue;
            }
            //process packets otherwise
            pb_process_block(pfifo, i, &blknum);
        }
    }
    pthread_exit(arg);
    return arg;
}
#ifdef BLOCK_TX
//transmission thread main function
static void * thread_tx(void *arg) {
    fifo_t * pfifo = (fifo_t *) arg;
    unsigned int i;
    while (1) {
        //cycling through all opened FIFOs
        for (i = 0; i < pfifo->fifo_num; ++i) {
            //thread cancellation point
            pthread_testcancel();
            //if transmission thread overlay index reached processing thread overlay index move to the next FIFO
            if (pfifo->fifo_array[i].curr_tx_overlay
                    == pfifo->fifo_array[i].curr_proc_overlay) {
                sched_yield();
                continue;
            }
            //transmit packets otherwise
            pb_transmit_block(pfifo, i);
        }
    }
    pthread_exit(arg);
    return arg;
}
#endif
#define NSEC_IN_SEC 1000000000UL
#define MAX_USER_PACKET_LENGTH_WO_LEN (MAX_USER_PACKET_LENGTH - sizeof(int16_t))
//Calculating new packets length
static inline int64_t calc_packet_length(uint64_t curr_byte_rate,
                                         int16_t data_packets,
                                         int16_t fec_packets,
                                         uint32_t inj_rate_max)
{
    //packet_payload_length = (PACKET_OVERHEAD * curr_byte_rate * (fec_packets + data_packets)) / ((param_injection_rate * data_packets) - (curr_byte_rate * (fec_packets + data_packets)))
    int64_t packet_length =
            (int64_t) (PACKET_OVERHEAD_LEN * curr_byte_rate
                    * (fec_packets + data_packets))
                    / ((int64_t) (inj_rate_max * data_packets)
                            - (int64_t) (curr_byte_rate
                                    * (fec_packets + data_packets)));
//  if(abs(packet_length % 10) >=5 )
//    packet_length += 10;
//  packet_length /= 10;
    fprintf(stderr, "Calculated packet len %ld\n", packet_length);
    if (packet_length < 0)
        packet_length = MAX_USER_PACKET_LENGTH_WO_LEN;
    else if (packet_length == 0) packet_length = 1;
    return packet_length;
}
//Calculate FEC packets number
static inline int16_t calc_fec_packets(uint64_t curr_byte_rate,
                                       int16_t data_packets,
                                       uint32_t inj_rate_max,
                                       int32_t packet_payload_length)
{
    int16_t fec_packets = ((int64_t) (inj_rate_max * data_packets)
            / (int64_t) (curr_byte_rate
                    * (PACKET_OVERHEAD_LEN / packet_payload_length + 1))
            - (int64_t) data_packets) * 10;
//  if((fec_packets % 10) >=5 )
//    fec_packets += 10;
//  fec_packets /= 10;
    if((fec_packets < 10) && (fec_packets > 0))
        fec_packets = 10;
    else if((fec_packets > -10) && (fec_packets < 0))
        fec_packets = -10;
    return fec_packets / 10;
}
//Simplify two numbers ratio by finding their GCD
//Also tweaking pfec_packets by +-1 in order to try to find bigger GCD
static void simplify_packets_ratio_iterative(int16_t * pdata_packets,
                                             int16_t * pfec_packets)
{
    int16_t data_packets = *pdata_packets;
    int16_t fec_packets = abs(*pfec_packets);
    if ((data_packets > 1) && (fec_packets > 1)) {
        uint16_t pkt_sum = data_packets + fec_packets;
        fprintf(stderr, "Raw packets fec=%d, data=%d\n", fec_packets,
                data_packets);
        uint16_t gcd = get_GCD(data_packets, fec_packets);
        uint16_t gcd_test = get_GCD(pkt_sum - fec_packets - 1, fec_packets + 1);
        if (gcd < gcd_test) {
            fec_packets += 1;
            data_packets = pkt_sum - fec_packets;
            fprintf(stderr, "-1 Found better gcd=%d > %d, fec=%d, data=%d\n",
                    gcd_test, gcd, fec_packets, data_packets);
            gcd = gcd_test;
        }
        gcd_test = get_GCD(pkt_sum - fec_packets + 1, fec_packets - 1);
        if (gcd < gcd_test) {
            fec_packets -= 1;
            data_packets = pkt_sum - fec_packets;
            fprintf(stderr, "+1 Found better gcd=%d > %d, fec=%d, data=%d\n",
                    gcd_test, gcd, fec_packets, data_packets);
            gcd = gcd_test;
        }
        *pdata_packets = data_packets / gcd;
        *pfec_packets = ((*pfec_packets < 0)? -1: 1) * fec_packets / gcd;
    }
}
//Simplify two numbers ratio by finding their GCD
static void simplify_packets_ratio(int16_t * pdata_packets,
                                   int16_t * pfec_packets)
{
    int16_t data_packets = *pdata_packets;
    int16_t fec_packets = *pfec_packets;
    if ((data_packets > 1) && (abs(fec_packets) > 1)) {
        uint16_t gcd = get_GCD(data_packets, abs(fec_packets));
        fprintf(stderr, "Negative fec=%d, data=%d, gcd=%d\n", fec_packets,
                data_packets, gcd);
        *pdata_packets = data_packets / gcd;
        *pfec_packets = fec_packets / gcd;
    }

}
//function used to calculate number of FEC and data packets as well as a packet length for the next transmission block
//data_packets_out and fec_packets_out are output parameters for data and FEC packets number respectively
//data_packets_out is also an input parameter for the completed block actual data packet count
// Return value is calculated packet length
static uint16_t calc_fec_params(int16_t * data_packets_out,
                                int16_t * fec_packets_out,
                                uint32_t inj_rate_max, uint64_t bytes_received)
{
    //structure for the saved tx block parameters
    struct tParamsInfo{
        uint16_t data_packets;
        int16_t fec_packets;
        uint16_t packet_len;
    };
    //Currently we save 2 previous tx block parameters
    static struct tParamsInfo prev_params[2] = {
            {.data_packets = 1, .fec_packets = 1, .packet_len = MAX_USER_PACKET_LENGTH_WO_LEN},
            {.data_packets = 1, .fec_packets = 1, .packet_len = MAX_USER_PACKET_LENGTH_WO_LEN}
    };
    // Explicit previous data packets number for convenience

    uint16_t prev_data_packets = *data_packets_out;
    //Current timestamp
    struct timespec ts_now;
    //Getting monotonic clock
    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    //Variable for the previous monotonic clock sample
    static struct timespec ts_saved = { 0, 0 };
    //Skipping first time block parameters calculation
    if ((ts_saved.tv_sec == 0) && (ts_saved.tv_nsec == 0)) {
        //Latching current timestamp for future use
        ts_saved = ts_now;
        //Returning default 1 to 1 data and FEC packets number
        *data_packets_out = 1;
        *fec_packets_out = 1;
        return (bytes_received > MAX_USER_PACKET_LENGTH_WO_LEN)? MAX_USER_PACKET_LENGTH_WO_LEN: bytes_received;
    }

    //Getting time delta between current and previous monotonic clock sample
    uint64_t time_delta = (ts_now.tv_sec * NSEC_IN_SEC + ts_now.tv_nsec)
            - (ts_saved.tv_sec * NSEC_IN_SEC + ts_saved.tv_nsec);

    ts_saved = ts_now;
    //Calculating byte rate of the data block between current and previous monotonic clock sample
    uint64_t curr_byte_rate = (10 * NSEC_IN_SEC * bytes_received) / time_delta;
    //Trying to perform rounding instead of truncating
    if ((curr_byte_rate % 10) >= 5) curr_byte_rate += 10;
    curr_byte_rate /= 10;
    /*Formulas used in further calculations
     param_injection_rate = ((fec_packets + data_packets) * (PACKET_OVERHEAD + bytes_received / prev_data_packets)) / (time_delta * data_packets / prev_data_packets)
     fec_packets = ((param_injection_rate * time_delta * data_packets / prev_data_packets) / (PACKET_OVERHEAD + bytes_received / prev_data_packets)) - data_packets
     fec_packets = ((param_injection_rate * time_delta * data_packets) / (PACKET_OVERHEAD * prev_data_packets + bytes_received)) - data_packets
     param_injection_rate = ((fec_packets + data_packets) * (PACKET_OVERHEAD + packet_nominal_lengh)) / (time_delta * data_packets / prev_data_packets)
     packet_nominal_lengh = ((param_injection_rate * time_delta * data_packets / prev_data_packets) / (fec_packets + data_packets)) - PACKET_OVERHEAD

     param_injection_rate = ((fec_packets + data_packets) * (PACKET_OVERHEAD * prev_data_packets + bytes_received)) / (time_delta * data_packets)
     param_injection_rate = ((fec_packets + data_packets) * prev_data_packets * (PACKET_OVERHEAD  + packet_payload_length)) / (time_delta * data_packets)
     time_delta = (packet_payload_length * prev_data_packets) / curr_byte_rate;
     param_injection_rate = ((fec_packets + data_packets) * curr_byte_rate * (PACKET_OVERHEAD  + packet_payload_length)) / (packet_payload_length * data_packets)
     (fec_packets + data_packets) / data_packets = (param_injection_rate * time_delta) / (prev_data_packets * (PACKET_OVERHEAD  + packet_payload_length))
     (fec_packets + data_packets) / data_packets = (param_injection_rate * packet_payload_length * prev_data_packets / curr_byte_rate) / (prev_data_packets * (PACKET_OVERHEAD  + packet_payload_length))
     (fec_packets + data_packets) / data_packets = (param_injection_rate * packet_payload_length ) / (curr_byte_rate * (PACKET_OVERHEAD  + packet_payload_length))
     (fec_packets + data_packets) / data_packets = (param_injection_rate) / (curr_byte_rate * (PACKET_OVERHEAD / packet_payload_length  + 1))

     fec_packets = (param_injection_rate * data_packets) / (curr_byte_rate * (PACKET_OVERHEAD / packet_payload_length  + 1)) - data_packets

     curr_byte_rate * (PACKET_OVERHEAD / packet_payload_length  + 1) = (param_injection_rate * data_packets) / (fec_packets + data_packets)
     (PACKET_OVERHEAD / packet_payload_length  + 1) = (param_injection_rate * data_packets) / (curr_byte_rate * (fec_packets + data_packets))
     PACKET_OVERHEAD / packet_payload_length = (param_injection_rate * data_packets) / (curr_byte_rate * (fec_packets + data_packets)) - 1
     packet_payload_length = PACKET_OVERHEAD / ((param_injection_rate * data_packets) / (curr_byte_rate * (fec_packets + data_packets)) - 1)
     packet_payload_length = (PACKET_OVERHEAD * curr_byte_rate * (fec_packets + data_packets)) / ((param_injection_rate * data_packets) - (curr_byte_rate * (fec_packets + data_packets)))
     */
    //Mean packet length of the received data block
    int32_t packet_payload_length = bytes_received / prev_data_packets;
    int16_t data_packets = 0;
    int16_t fec_packets = 0;

    uint64_t old_overall_byte_rate = ((prev_params[0].fec_packets + prev_params[0].data_packets) * curr_byte_rate
                * (PACKET_OVERHEAD_LEN + prev_params[0].packet_len))
                / (prev_params[0].packet_len * prev_params[0].data_packets);
    fprintf(stderr,
            "\n>Fec calc, packet_payload_length = %d, bytes_received = %ld, prev_data_packets = %d, time_delta=%ld ns, payload data rate=%ld, total data rate=%ld\n",
            packet_payload_length, bytes_received, prev_data_packets, time_delta, curr_byte_rate, old_overall_byte_rate);

    //trying 3 iterations to find optimal values for block parameters (avoids endless loops)
    for (uint8_t i = 0; i < 3; ++i) {
        fprintf(stderr, ">>iter=%d\n", i);
//        time_delta = (NSEC_IN_SEC * packet_payload_length * prev_data_packets)
//                / curr_byte_rate;
//    int64_t fec_part_ratio_old = ((int64_t) (inj_rate_max * time_delta)
//        / (int64_t) (prev_data_packets * (PACKET_OVERHEAD_LEN + packet_payload_length)))
//        - (int64_t) (1 * NSEC_IN_SEC);
        //Calculating FEC part of the block ration relative to the data part, multiplied by NSEC_IN_SEC, to keep fractional part
        int64_t fec_part_ratio = (int64_t) (NSEC_IN_SEC * inj_rate_max)
                / (int64_t) ((curr_byte_rate * PACKET_OVERHEAD_LEN)
                        / packet_payload_length + curr_byte_rate)
                - (int64_t) (1 * NSEC_IN_SEC);
        fprintf(stderr,
                ">>>prev_data_packets=%d, packet_payload_length = %d, bytes_received=%ld, "
                "ratio=%f, param_injection_rate=%d\n",
                prev_data_packets, packet_payload_length,
                bytes_received, (float) fec_part_ratio / NSEC_IN_SEC,
                inj_rate_max);
        // The case when FEC part is less than data part but is still positive, meaning FEC packets number is less than data packets number
        if ((fec_part_ratio < (1 * NSEC_IN_SEC)) && (fec_part_ratio > 0)) {
            //Check for packet length within the limits, effective mostly on second and third interation
            if (packet_payload_length < MAX_USER_PACKET_LENGTH_WO_LEN) {
                //Trying to make fec packets = data packets = prev_data_packets by raising packet payload length

//        packet_payload_length = ((int64_t)PACKET_OVERHEAD_LEN * 2 * (int64_t)curr_byte_rate) / ((int64_t)inj_rate_max  - 2 * (int64_t)curr_byte_rate) + 1;
//        for (int p = packet_payload_length; p < 10; p++){
//          int64_t fec_part_ratio = (int64_t) (NSEC_IN_SEC * inj_rate_max) /
//              (int64_t)((curr_byte_rate * PACKET_OVERHEAD_LEN) / p + curr_byte_rate) - (int64_t) (1 * NSEC_IN_SEC);
//          fprintf(stderr, ">>>Iter prev_data_packets=%d, packet_payload_length = %d, time_delta=%ld ns, bytes_received=%ld, "
//                      "ratio=%f, param_injection_rate=%d, data rate=%ld\n",
//                      prev_data_packets, p, time_delta, bytes_received,
//                      (float)fec_part_ratio/NSEC_IN_SEC,/*(float)fec_part_ratio_old/NSEC_IN_SEC,*/
//                     inj_rate_max, curr_byte_rate);
//        }
                //trying to keep FEC/DATA ratio to 1, by raising packet length
                packet_payload_length = calc_packet_length(curr_byte_rate, 1, 1,
                                                           inj_rate_max) + 1;
                fprintf(stderr, "+++New packet length %d\n",
                        packet_payload_length);
                //Capping packet length to the limit
                if (packet_payload_length > MAX_USER_PACKET_LENGTH_WO_LEN) {
                    packet_payload_length = MAX_USER_PACKET_LENGTH_WO_LEN;
                }
                //Going to the second iteration, hoping to get FEC/DATA ratio 1
                continue;
            }
            //We failed to achieve FEC/DATA ratio 1, starting with previous block data packets number
            data_packets = prev_data_packets;
            uint64_t fec_part = fec_part_ratio * data_packets;

            //If fec packets num is more than 1 (times NSEC_IN_SEC for precision) trying to reuse previous block
            //data packets number and calculate new FEC packets number
            if (fec_part > (1 * NSEC_IN_SEC)) {
//          fec_packets = ((inj_rate_max * time_delta * data_packets)
//              / (PACKET_OVERHEAD_LEN * prev_data_packets + bytes_received))
//              / NSEC_IN_SEC - data_packets;
//        fec_packets = ((inj_rate_max * time_delta * data_packets)
//                    / (NSEC_IN_SEC * prev_data_packets * (PACKET_OVERHEAD_LEN  + packet_payload_length)))
//                     - data_packets;
                //Calculating new FEC packets number
                fec_packets = calc_fec_packets(curr_byte_rate, data_packets,
                                               inj_rate_max,
                                               packet_payload_length);
            //If FEC packets num is 1 (times NSEC_IN_SEC for precision) using it as is
            } else if (fec_part == (1 * NSEC_IN_SEC)) {
                fec_packets = 1;
            //So the FEC packets num is lower the 1 (times NSEC_IN_SEC for precision), that means that we can not use old block data packets number
            } else {
                //Making a scale multiplier to use the whole MAX_PACKETS_PER_BLOCK scale for packet numbers calculation
                //this raises packets ratio precision
                uint64_t scale = ((uint64_t) MAX_PACKETS_PER_BLOCK * NSEC_IN_SEC)
                        / (fec_part + (data_packets * NSEC_IN_SEC));
                //Scaling previous block data packets number
                data_packets = data_packets * scale;
//          fec_packets = ((inj_rate_max * time_delta * data_packets)
//              / (PACKET_OVERHEAD_LEN * prev_data_packets + bytes_received))
//              / NSEC_IN_SEC - data_packets;
//        fec_packets = ((inj_rate_max * time_delta * data_packets)
//                    / (NSEC_IN_SEC * prev_data_packets * (PACKET_OVERHEAD_LEN  + packet_payload_length)))
//                     - data_packets;
                //Calculation new FEC packets number based on the scaled data packets
                fec_packets = calc_fec_packets(curr_byte_rate, data_packets,
                                               inj_rate_max,
                                               packet_payload_length);
                //If we exceed total packets per block constant, capping the packets sum to MAX_PACKETS_PER_BLOCK
                if ((fec_packets + data_packets) > MAX_PACKETS_PER_BLOCK)
                    fec_packets = MAX_PACKETS_PER_BLOCK - data_packets;
            }
            //Trying to find greatest common denominator and simplify packets ratio
            simplify_packets_ratio_iterative(&data_packets, &fec_packets);
//      packet_payload_length = ((inj_rate_max * time_delta * data_packets
//          / prev_data_packets) / (fec_packets + data_packets)) / NSEC_IN_SEC
//          - PACKET_OVERHEAD_LEN;
            //Based on a new found data and FEC packets number calculate new block packet length
            packet_payload_length = calc_packet_length(curr_byte_rate,
                                                       data_packets,
                                                       fec_packets,
                                                       inj_rate_max);
            //Capping packet length to the limit
            if (packet_payload_length > MAX_USER_PACKET_LENGTH_WO_LEN) {
                fprintf(stderr, "Wrong packet length %d\n",
                        packet_payload_length);
                packet_payload_length = MAX_USER_PACKET_LENGTH_WO_LEN;
//          fec_packets = ((inj_rate_max * time_delta * data_packets)
//              / (PACKET_OVERHEAD_LEN * prev_data_packets + bytes_received))
//              / NSEC_IN_SEC - data_packets;
                //Since packet length was changed, packet ratio recalculation is needed, going to the second iteration
                continue;
            }
        //This mean that we are exceeding maximum injection rate with current parameters, trying to pick better ones
        } else if (fec_part_ratio < 0) {
            //If packet length is no yet maximum
            if (packet_payload_length < MAX_USER_PACKET_LENGTH_WO_LEN) {
                //Trying to reach fec packets = data packets = 1 by raising packet payload length
//        packet_payload_length = ((int64_t)PACKET_OVERHEAD_LEN * 2 * (int64_t)curr_byte_rate) / ((int64_t)inj_rate_max - 2 * (int64_t)curr_byte_rate) + 1;
                packet_payload_length = calc_packet_length(curr_byte_rate, 1, 1,
                                                           inj_rate_max);
                //Adding +1 byte to packet length to ty to reduce future number of iterations
                packet_payload_length++;

                //Capping packet length to the limit
                if (packet_payload_length > MAX_USER_PACKET_LENGTH_WO_LEN) {
                    packet_payload_length = MAX_USER_PACKET_LENGTH_WO_LEN;
                }
                fprintf(stderr, "+++New packet length %d\n",
                                        packet_payload_length);
                //Going to the second iteration, hoping that with the new parameters we will not hit maximum injection limit again
                continue;
            }
            //Breaking the loop, if we already been here setting data packets number to half maximum,
            //exit the loop using previously calculated parameters
            if(data_packets == prev_data_packets)
                break;
            //If packet length is maximum already,trying to calculate packets numbers by half maximum packets per block
            data_packets = MAX_PACKETS_PER_BLOCK / 2;
//      fec_packets = ((inj_rate_max * time_delta * data_packets)
//          / (NSEC_IN_SEC * prev_data_packets * (PACKET_OVERHEAD_LEN  + packet_payload_length)))
//           - data_packets;
            //Then calculating FEC packets number, here it can be negative
            //meaning we need to skip several data packets in the next data block to maintain maximum
            //injection rate boundary
            fec_packets = calc_fec_packets(curr_byte_rate, data_packets,
                                           inj_rate_max, packet_payload_length);
            //Trying to find greatest common denominator and simplify packets ratio
            simplify_packets_ratio(&data_packets, &fec_packets);
            //Altering completed block data packets number for further iterations calculations
            prev_data_packets = data_packets;
//            if (packet_payload_length >= MAX_USER_PACKET_LENGTH_WO_LEN) break;
//      packet_payload_length = ((inj_rate_max * time_delta * data_packets
//          / prev_data_packets) / (fec_packets + data_packets)) / NSEC_IN_SEC
//          - PACKET_OVERHEAD_LEN;



            //Recalculating new packet length with the new parameters
            packet_payload_length = calc_packet_length(curr_byte_rate,
                                                       data_packets,
                                                       fec_packets,
                                                       inj_rate_max);
            //Capping packet length to the limit
            if (packet_payload_length > MAX_USER_PACKET_LENGTH_WO_LEN) {
                fprintf(stderr, "Wrong packet length %d\n",
                        packet_payload_length);
                packet_payload_length = MAX_USER_PACKET_LENGTH_WO_LEN;
                //Trying again with another iteration, with the new packet length
                continue;
            }


            fprintf(stderr, "New packet length=%d\n", packet_payload_length);
        //This means FEC part ratio is equal or bigger than data part ratio, which means we can use FEC packets to data packets ratio 1
        } else {
            data_packets = 1;
            fec_packets = 1;
            //trying lower packet length to reduce fec ratio, and reduce data receive wait time (latency)
//      packet_payload_length = calc_packet_length(curr_byte_rate, data_packets, fec_packets, inj_rate_max);
//      for (int p = packet_payload_length; p > 0; p--){
//        uint64_t new_byte_rate = ((fec_packets + data_packets) * curr_byte_rate * (PACKET_OVERHEAD_LEN  + p)) /
//              (p * data_packets);
//        fprintf(stderr, "Iter byte rate: %ld, prev_data_packets=%d, bytes_received=%ld, fec_packets=%d, data_packets=%d, packet_payload_length=%d\n",
//              new_byte_rate, prev_data_packets, bytes_received, fec_packets,
//              data_packets, p);
//      }
            //Calculating the new packet length with FEC=data=1 packets numbers
            packet_payload_length = calc_packet_length(curr_byte_rate, 1, 1,
                                                       inj_rate_max) + 1;
            //Capping packet length to the limit
            if (packet_payload_length > MAX_USER_PACKET_LENGTH_WO_LEN) {
                packet_payload_length = MAX_USER_PACKET_LENGTH_WO_LEN;
            }
            fprintf(stderr, "FEC ratio > 1, new packet length=%d\n",
                    packet_payload_length);
        }
        break;

    }
//  uint64_t new_byte_rate = NSEC_IN_SEC * (data_packets + fec_packets)
//      * (packet_payload_length + PACKET_OVERHEAD_LEN)
//      / (time_delta * data_packets / prev_data_packets);
    //Illustrational calculation for the new data rate, to check that it is less than maximum injection rate
    uint64_t new_byte_rate = ((fec_packets + data_packets) * curr_byte_rate
            * (PACKET_OVERHEAD_LEN + packet_payload_length))
            / (packet_payload_length * data_packets);
    fprintf(stderr,
            "New byte rate: %ld, prev_data_packets=%d, bytes_received=%ld, fec_packets=%d, data_packets=%d, packet_payload_length=%d\n",
            new_byte_rate, prev_data_packets, bytes_received, fec_packets,
            data_packets, packet_payload_length);



    //Saving data block parameters, by shifting previous parameters array backlog one place
    //In the same time spurious traffic rate filtering is performed here
    for(int16_t p = (sizeof(prev_params) / sizeof(prev_params[0])) - 1,
               steady_params = p; p >= 0; --p) {
        fprintf(stderr, "+++p=%d, fec=%d, data=%d, plen=%d, steady_params=%d\n",
                        p, prev_params[p].data_packets, prev_params[p].fec_packets,
                        prev_params[p].packet_len, steady_params);
        //Check if it is a newest member of the backlog
        if (p == 0) {
            //If backlog members show changing parameters in the past, it is ok to change next block parameters right away
            //Or if previous parameters had data packets number more than 1
            //Generally it is ok to filter out one spurious fast packet leaving it to the NIC input buffer to straighten ijection rate out
            //But if there were more than 1 data packets before, that means traffic was already raising, so letting several data packets along with FEC packets
            //oversaturate NIC input buffer is not desirable, so we are taking the risk and not filtering multiple data packets case
            if ( !steady_params || (prev_params[p].data_packets > 1)) {
                //Filling backlog entry parameters with the newly calculated ones
                prev_params[p].data_packets = data_packets;
                prev_params[p].fec_packets = fec_packets;
                prev_params[p].packet_len = packet_payload_length;
            //If all backlog members showed steady block parameters (traffic rate was stable before)
            //skipping the first time parameters update, but jerking the oldest parameters backlog entry
            //to make sure next time parameters update will happen due to steady_params will be 0
            } else {
                //Filling backlog entry parameters with the newly calculated ones
                prev_params[steady_params].data_packets = data_packets;
                //Mangling FEC parameter to make sure next steady_params comparison will fail
                prev_params[steady_params].fec_packets = fec_packets + 1;
                //If we have data==fec==1 packets number, it is generally ok to change the packet length
                if(data_packets == 1)
                    prev_params[p].packet_len = packet_payload_length;
            }
        } else {
            //Checking if FEC and data packet numbers parameters were stable between two adjacent backlog entries
            //If previous such check already failed skip all successive checks with steady_params = 0 result
            if ( steady_params &&
                    ((prev_params[p].data_packets != prev_params[p - 1].data_packets) ||
                            (prev_params[p].fec_packets != prev_params[p - 1].fec_packets)) )
                steady_params = 0;
            fprintf(stderr, "+++steady_params=%d\n", steady_params);
            //Propagating block parameters from the newer backlog entry to the older one
            prev_params[p].data_packets = prev_params[p - 1].data_packets;
            prev_params[p].fec_packets = prev_params[p - 1].fec_packets;
            prev_params[p].packet_len = prev_params[p - 1].packet_len;
        }

    }

    //Returning calculated values
    *data_packets_out = prev_params[0].data_packets;
    *fec_packets_out = prev_params[0].fec_packets;
    return prev_params[0].packet_len;
}

static int allow_tx_packet(int16_t pass_pkts, int16_t skip_pkts, uint8_t * pkt_index){
    //algorithm for data rate limiting by evenly distributing pass and skip packets
    unsigned int pass_ratio = (pass_pkts + abs(skip_pkts)) / pass_pkts;
    unsigned int skip_ratio = (pass_pkts + abs(skip_pkts)) / abs(skip_pkts);
    //One of the ratios are always 1 another could be any, except for the case pass_pkts=skip_pkts where both ratios equal to 2
    int allow_pass = 0;
    static int tie_breaker = 0;
    *pkt_index += 1;
    if (((*pkt_index % skip_ratio) == 0) && ((*pkt_index % pass_ratio) == 0)) {
        if (skip_ratio > pass_ratio) {
            //This means pass_ratio=1
            //We are limiting skip packets by the product of skip_ratio * skip_pkts, which should be less than pkt_index
            if(*pkt_index <= (skip_ratio * skip_pkts))
                allow_pass = 0;
            else
                allow_pass = 1;
        } else if (pass_ratio > skip_ratio) {
            //This means skip_ratio=1
            //We are limiting skip packets by the product of pass_ratio * pass_pkts, which should be less than pkt_index
            if(*pkt_index <= (pass_ratio * pass_pkts))
                allow_pass = 1;
            else
                allow_pass = 0;
        } else {
            allow_pass = tie_breaker++;
            tie_breaker %= 2;
        }
    } else if ((*pkt_index % skip_ratio) == 0) {
        allow_pass = 0;
    } else if ((*pkt_index % pass_ratio) == 0) {
        allow_pass = 1;
    }

    return allow_pass;
}

// Options parser
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    /* Get the input argument from argp_parse, which we
     know is a pointer to our opts structure. */
    struct opts_t *opts = (struct opts_t *) state->input;

    switch (key) {
        case 'r':  // retransmissions
            opts->fec_packets_per_block = arg ? atoi(arg) : 1;
            break;
        case 'f':  // MTU
            opts->packet_length = arg ? atoi(arg) : MAX_USER_PACKET_LENGTH;
            if (opts->packet_length > MAX_USER_PACKET_LENGTH) {
                printf("Packet length is limited to %d bytes (you requested %d bytes)\n",
                MAX_USER_PACKET_LENGTH,
                       (int) opts->packet_length);
                argp_usage(state);
            }
            break;
        case 'p':  //port
            opts->port = arg ? atoi(arg) : 0;
            break;
        case 'b':  //retransmission block size
            opts->data_packets_per_block = arg ? atoi(arg) : 1;
            break;
        case 'm':  //minimum packet length
            opts->min_packet_length = arg ? atoi(arg) : 0;
            break;
        case 's':  //how many streams (fifos) do we have in parallel
            opts->fifo_count = arg ? atoi(arg) : 1;
            break;
        case 'x':  //how often is a block transmitted
            opts->transmission_count = arg ? atoi(arg) : 1;
            break;
        case 'i':  //injection rate
            opts->injection_rate = arg ? atoi(arg) : 24;
            break;
        case 'a':  //frame rate
            opts->frame_rate = arg ? atoi(arg) : 80;
            break;
#ifdef INTERLEAVED
            case 't':  //interleaved transmission
            opts->interleaved = 1;
            break;
#endif
        case 'd':  //duplicated transmission
            opts->duplicated = 1;
            break;
        case 'w':  //wlan list
            if (arg) {
                if (strlen(opts->wlan_list) + strlen(arg) < WLAN_BUFFER_SIZE) {
                    if (opts->wlan_list[0]) {
                        strncat(opts->wlan_list, ";", 1);
                    }
                    strncat(opts->wlan_list, arg, 10);
                }
            }
            break;
        case ARGP_KEY_END:
#ifndef TEST_EN
            if(!opts->wlan_list) {
                argp_usage (state);
                break;
            }
#endif
            if (opts->min_packet_length > opts->packet_length) {
                fprintf(
                stderr,
                        "Your minimum packet length is higher that your maximum packet length (%d > %d)\n",
                        (int) opts->min_packet_length,
                        (int) opts->packet_length);
                opts->min_packet_length = opts->packet_length;
                argp_usage(state);
                break;
            }
            if (opts->fifo_count > MAX_FIFOS) {
                fprintf(
                stderr,
                        "The maximum number of streams (FIFOS) is %d (you requested %d)\n",
                        MAX_FIFOS,
                        opts->fifo_count);
                argp_usage(state);
                break;
            }

            if (opts->data_packets_per_block > MAX_DATA_OR_FEC_PACKETS_PER_BLOCK
                    || opts->fec_packets_per_block
                            > MAX_DATA_OR_FEC_PACKETS_PER_BLOCK) {
                fprintf(
                stderr,
                        "Data and FEC packets per block are limited to %d (you requested %d data, %d FEC)\n",
                        MAX_DATA_OR_FEC_PACKETS_PER_BLOCK,
                        opts->data_packets_per_block,
                        opts->fec_packets_per_block);
                argp_usage(state);
                break;
            }

            if ((opts->frame_rate < 15) && (opts->frame_rate > 200)) {
                fprintf(stderr,
                        "Frame rate supplied %d is outside limits: [15, 200] \n",
                        opts->frame_rate);
                argp_usage(state);
                break;
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = { cmd_options, parse_opt, NULL, doc };

//main function
int main(int argc, char *argv[])
{

    int i;

    char fBrokenSocket = 0;
    int pcnt = 0;
//	time_t start_time;
//	uint8_t packet_transmit_buffer[MAX_PACKET_LENGTH];
//	size_t packet_header_length = 0;
#ifdef SELECT_EN
    fd_set fifo_set;
    int max_fifo_fd = -1;
#endif

//default parameters FECs=1 DATA=1 param_packet_length=MAX_USER_PACKET_LENGTH param_injection_rate=24 param_frame_rate=80 param_port=0
    struct opts_t run_opts = { 0, 1, MAX_USER_PACKET_LENGTH, 1, 0, 1, 1, 24, 80,
            0, 0, { 0 } };
//processing command line arguments
    argp_parse(&argp, argc, argv, 0, 0, &run_opts);

    timer_t tp_timer;
//creating statistics timer
    if (timer_create(CLOCK_MONOTONIC, NULL, &tp_timer) == -1) {
        perror("Failed to create timer\n");
        return 1;
    }
//garbage collector push
    on_exit(gc_timer, tp_timer);
//mapping all available signals to our signal handler
    for (i = 1; i <= SIGPWR; ++i) {
        if (i != SIGKILL) signal(i, sig_handler);
    }
//setting the timer for cyclic alarm each 2 sec
    const struct itimerspec tp_int = { .it_interval = { 2, 0 }, .it_value = { 2,
            0 } };
    if (timer_settime(tp_timer, 0, &tp_int, NULL) == -1) {
        perror("Failed to set timer timer, aborting...\n");
        return 1;
    }

#ifdef SELECT_EN
    fifo_create_select_set(fifo, param_fifo_count, &fifo_set, &max_fifo_fd);
#endif
//initialized main FIFO structure with supplied parameters
    fifo_init(&fifo, run_opts.fifo_count, run_opts.data_packets_per_block,
              run_opts.fec_packets_per_block, run_opts.port,
              run_opts.packet_length, run_opts.injection_rate);
//garbage collector push
    on_exit(gc_fifo, &fifo);
//maximum injection rate
    run_opts.injection_rate = run_opts.injection_rate * 10e6 / 8;

    if (run_opts.injection_rate > INJ_RATE_MAX) run_opts.injection_rate =
            INJ_RATE_MAX;
#ifndef TEST_EN
    char szErrbuf[PCAP_ERRBUF_SIZE];
    pcap_t *ppcap = NULL;

    char separator[2] = ”;”;
    char *arg_value = strtok (run_opts.wlan_list, separator);
// open the WLAN interfaces through PCAP
    while (arg_value != NULL) {
        szErrbuf[0] = '\0';
        ppcap = pcap_open_live(arg_value, run_opts.packet_length, 0, 20,
                szErrbuf);
        if (ppcap == NULL) {
            fprintf(stderr, "Unable to open interface %s in pcap: %s\n",
                    arg_value, szErrbuf);
            return (1);
        }
        //non-blocking operation
        pcap_setnonblock(ppcap, 0, szErrbuf);
        fifo.ppcap_arr = (pcap_t **) realloc(fifo.ppcap_arr,
                sizeof(pcap_t *) * ++fifo.num_pcap);
        fifo.ppcap_arr[fifo.num_pcap - 1] = ppcap;
        arg_value = strtok (NULL, separator);
    }
#else
    char separator[2] = ";";
    char *arg_value = strtok(run_opts.wlan_list, separator);
    int wlan_list_count = 0;
    while (arg_value != NULL) {
        wlan_list_count++;
        arg_value = strtok(NULL, separator);
    }
    fifo.num_pcap = wlan_list_count;
#endif
//initialize forward error correction
    fec_init();

//tx retransmission set up
    fifo.transmission_count = run_opts.transmission_count;
#ifdef INTERLEAVED
    fifo.interleaved = run_opts.interleaved;
#endif
//set duplicated/load shared operation with transmission multipathing
    fifo.duplicated = run_opts.duplicated;
//open FIFOs
    fifo_open(&fifo, run_opts.fifo_count);
#ifndef SELECT_EN
//creating EPoll handle
    int epfd = epoll_create(1);
    if (epfd == -1) {
        perror("Failed to create epoll descriptor, aborting...\n");
        return 1;
    }
//garbage collector push
    on_exit(gc_epoll, &epfd);
//setting EPoll to react on arriving data
    struct epoll_event eearr[8];
    for (i = 0; i < run_opts.fifo_count; ++i) {
        eearr[i].events = EPOLLIN;
        eearr[i].data.u32 = i;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fifo.fifo_array[i].fd, &eearr[i])
                == -1) {
            perror("Failed to add FIFO fd to epoll, aborting\n");
            return 1;
        }

    }
#endif
    pthread_t proc_thread = 0;

    pthread_attr_t pattr;
//raising pthread scheduling priority for new threads
    struct sched_param pt_nice = { -19 };
    if (pthread_attr_init(&pattr)) {
        perror("Failed to initialize a thread attributes, aborting...\n");
        return 1;
    }
    if (pthread_attr_setinheritsched(&pattr, PTHREAD_EXPLICIT_SCHED)
            && pthread_attr_setschedpolicy(&pattr, SCHED_OTHER)
            && pthread_attr_setschedparam(&pattr, &pt_nice)) {
        perror("Failed to set a thread attributes, aborting...\n");
        return 1;
    }
//garbage collector push
    on_exit(gc_pattr, &pattr);
//raising pthread scheduling priority for main thread
    nice(-20);
//creating processing thread
    if (pthread_create(&proc_thread, &pattr, thread_proc, &fifo)) {
        perror("Failed to create processing thread, aborting...\n");
        return 1;
    }
//garbage collector push
    on_exit(gc_pthr, &proc_thread);
#ifdef BLOCK_TX
    pthread_t tx_thread = 0;
//creating transmission thread
    if (pthread_create(&tx_thread, &pattr, thread_tx, &fifo)) {
        perror("Failed to create transmission thread, aborting...\n");
        return 1;
    }
//garbage collector push
    on_exit(gc_pthr, &tx_thread);
#endif
//statistics time latch
    struct timespec ts_saved;
    uint64_t bytes_received = 0;
    clock_gettime(CLOCK_MONOTONIC, &ts_saved);
//main busy loop
    size_t run_packet_length = run_opts.packet_length;
    size_t run_min_packet_length = run_opts.min_packet_length;
    fprintf(stderr, "run_min_packet_length = %ld\n", run_min_packet_length);
    while (!fBrokenSocket) {
#ifdef SELECT_EN
        fd_set rdfs;
        int ret;

        rdfs = fifo_set;

        wait for new data on the fifos
        ret = select(max_fifo_fd + 1, &rdfs, NULL, NULL, NULL);
        if(ret < 0) {
            perror("select");
            return (1);
        }
        //cycle through all fifos and look for new data
        for(i=0; i<run_opts.fifo_count && ret; ++i) {
            if(!FD_ISSET(fifo[i].fd, &rdfs)) {
                continue;
            }

            ret--;
#endif
        //waiting on EPoll
        int nfds;
        do {
            nfds = epoll_wait(epfd, eearr, 8, -1);
        } while (nfds < 0 && errno == EINTR);
        if (nfds < 0) {
            perror("epoll_wait failed, aborting...\n");
            return 1;
        }

        int j = 0;
        //created a bitmask out of ready FIFOs
        uint64_t nfds_mask = ~(0xFFFFFFFFffffffff << nfds);
        uint32_t curr_byte_rate;
        //cycling through ready FIFOs
        while (nfds_mask) {
            i = eearr[j].data.u32;
//            printf("FIFO #%d ready\n", i);
            unsigned int chk_rx_ovl = (fifo.fifo_array[i].curr_rx_overlay + 1)
                    % OVERLAY_NUM;
            unsigned int used_rx_ovl = fifo.fifo_array[i].curr_rx_overlay;
//            printf("chk_rx_ovl=%d, used_rx_ovl=%d, curr_proc_overlay=%d\n",
//            		chk_rx_ovl, used_rx_ovl, fifo.fifo_array[i].curr_proc_overlay);
            //checking if there is a free overlay to start receiving data, check with proc and tx threads
            if ((chk_rx_ovl == fifo.fifo_array[i].curr_proc_overlay)
            // For latency reduction, block transmit is disabled, we send every ready packet right away, so no need in 3rd thread
#ifdef BLOCK_TX
                    || (chk_rx_ovl == fifo.fifo_array[i].curr_tx_overlay)
#endif
                    || !((1 << j) & nfds_mask)) {
                //if no free overlay move to the next FIFO
                j = (j + 1) % nfds;
//                printf("j=%d, nfds=%d, nfds_mask=%x\n", j, nfds, nfds_mask);
                sched_yield();
                continue;
            }

            packet_buffer_t *pb = &fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                    .pbl_data[fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                    .curr_pb_data];

            //if the buffer is fresh we add a payload header
//			if(pb->len == 0) {
//                pb->len += sizeof(payload_header_t); //make space for a length field (will be filled later)
//			}

            //read the data
            struct pkt_struct_t * ps = (struct pkt_struct_t *) pb->data;
            debug_print(
                    ">>>buff: %p, offset: %ld, len: %ld, curr_pb_data: %d, ovl: %d, fifo: %d\n",
                    ps->payload.sPayload.dataBuff, pb->len, run_packet_length,
                    fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data,
                    used_rx_ovl, i);
            int inl = read(fifo.fifo_array[i].fd,
                           ps->payload.sPayload.dataBuff + pb->len,
                           run_packet_length - pb->len);
            if ((inl < 0) || (inl > (int) (run_packet_length - pb->len))) {
                fprintf(
                stderr,
                        "inl: %d, buff: %p, offset: %ld, len: %ld, curr_pb_data: %d, ovl: %d, fifo: %d\n",
                        inl, ps->payload.sPayload.dataBuff, pb->len,
                        run_packet_length,
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data,
                        used_rx_ovl, i);
                perror("Error reading stdin");
                return 1;
            }

            if (inl == 0) {
                //EOF
                fprintf(
                stderr,
                        "Warning: Lost connection to fifo %d. Please make sure that a data source is connected\n",
                        i);
                usleep(1e5);
                continue;
            }

            pb->len += inl;


            //check if we read enough data to move tothe next packet
            if (pb->len >= run_min_packet_length) {




//                payload_header_t *ph = (payload_header_t*)pb->data;
//                ph->data_length = pb->len - sizeof(payload_header_t); //write the length into the packet. this is needed since with fec we cannot use the wifi packet lentgh anymore. We could also set the user payload to a fixed size but this would introduce additional latency since tx would need to wait until that amount of data has been received
                //RX statistics counter
                if(run_min_packet_length)
                    bytes_received += pb->len;
                else
                    bytes_received += inl;

                //filling packet header data
                //actual data length
                ps->payload.sPayload.len = pb->len;
                //current block packet length
                ps->payload_hdr.nominal_packet_length = fifo.fifo_array[i]
                        .pb_overlay[used_rx_ovl].packet_payload_length + sizeof(ps->payload.sPayload.len);
                //current FEC ratio
                //If FEC part is negative it means we are rate limiting thus sending only data packets without FEC
                ps->payload_hdr.num_data_blocks =
                        (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio > 0)?
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio: 1;
                //current DATA ratio
                //filtering negative FEC ratio, which mean we actually need to skip packets to limit the rate
                ps->payload_hdr.num_fecs_blocks =
                        (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio > 0)?
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio: 0;
                //statistics packet count
                pcnt++;
                fprintf(stderr,
                        "Bytes received combined %ld, packet_length %ld, min_packet_length %ld, num_data_blocks %d, num_fecs_blocks %d, pcnt %d\n",
                        bytes_received, run_packet_length,
                        run_min_packet_length, ps->payload_hdr.num_data_blocks,
                        ps->payload_hdr.num_fecs_blocks, pcnt);
                //check if this block is finished
                uint16_t data_pkts_in_block = (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio > 0)?
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio - 1: 0;
                if (fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data
                        >= data_pkts_in_block) {
                    //Registering actual data packets sent, for pb_process_block to clean up properly
                    fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio =
                            fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data + 1;
                    //Recording actual received data packets number
                    fprintf(stderr,"Fec packets: %d\n", fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio);
                    int16_t prev_data_packets = (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio < 0)?
                            1:(fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data + 1);
                    int16_t future_fec_packets;
                    uint16_t future_packet_length = calc_fec_params(&prev_data_packets,
                                                                    &future_fec_packets,
                                                                    run_opts.injection_rate,
                                                                    bytes_received);
                    if((future_fec_packets >= 0) ||
                            ((future_fec_packets < 0) && (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio > 0))) {
                        fprintf(stderr, "Moving to the next overlay from no rate limit: future_fec_packets=%d, prev_data_packets=%d, future_packet_length=%d\n",
                                future_fec_packets, prev_data_packets, future_packet_length);
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data++;
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].skip_pb_data = 0;
                        //moving to the next overlay
                        fifo.fifo_array[i].curr_rx_overlay = (fifo.fifo_array[i]
                                .curr_rx_overlay + 1) % OVERLAY_NUM;

                        used_rx_ovl = fifo.fifo_array[i].curr_rx_overlay;
                    } else {
                        fprintf(stderr, "Received pb->len=%d, needed %d\n",
                                pb->len, /*fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length*/ future_packet_length);
                        if(pb->len >= /*fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length*/ future_packet_length) {
                            if (fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data >=
                                    (prev_data_packets - 1)) {
                                fprintf(stderr, "Moving to the next overlay from rate limit: future_fec_packets=%d, prev_data_packets=%d, future_packet_length=%d\n",
                                                                future_fec_packets, prev_data_packets, future_packet_length);

                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data++;
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].skip_pb_data = 0;
                                //moving to the next overlay
                                fifo.fifo_array[i].curr_rx_overlay = (fifo.fifo_array[i]
                                        .curr_rx_overlay + 1) % OVERLAY_NUM;

                                used_rx_ovl = fifo.fifo_array[i].curr_rx_overlay;
                            } else {
                                fprintf(stderr, "Continuing overlay: future_fec_packets=%d, prev_data_packets=%d, future_packet_length=%d, curr_pb_data=%d\n",
                                                                future_fec_packets, prev_data_packets, future_packet_length, fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data);
#ifdef RATE_LIMITER
                                    if(allow_tx_packet(prev_data_packets, future_fec_packets, &fifo.fifo_array[i].pb_overlay[used_rx_ovl].skip_pb_data)) {
                                        fprintf(stderr, "Transmitting packet: curr_pb_data=%d, skip_pb_data=%d\n",
                                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data,
                                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].skip_pb_data);
                                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data++;
                                    } else {
                                        fprintf(stderr, "Skipping packet: curr_pb_data=%d, skip_pb_data=%d\n",
                                                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data,
                                                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].skip_pb_data);
                                         pb->len = 0;
                                    }
#else
                                    future_packet_length = MAX_USER_PACKET_LENGTH_WO_LEN;
                                    fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data++;
#endif
                            }
                        }

                    }

                    fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                            .packet_payload_length = future_packet_length;

                    fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                    .data_part_ratio = prev_data_packets;

                    fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                    .fec_part_ratio = future_fec_packets;

//                            + sizeof(ps->payload.sPayload.len);
                    fprintf(stderr,
                            "After calc_fec, plen %d, data %d, fec %d\n",
                            fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length,
                            fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio,
                            fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio);
                    //for now
//                    if (fifo.fifo_array[i].pb_overlay[used_rx_ovl]
//                            .fec_part_ratio < 0) fifo.fifo_array[i].pb_overlay[used_rx_ovl]
//                            .fec_part_ratio = 0;

#ifdef OLD_FEC_ALG
                    //generating FEC and DATA ratios and packet payload size for the next block (overlay)
                    struct timespec ts_now;
                    clock_gettime(CLOCK_MONOTONIC, &ts_now);
                    //getting previous block data rate
                    uint64_t time_delta = (ts_now.tv_sec * 1000000000 + ts_now.tv_nsec)
                    - (ts_saved.tv_sec * 1000000000 + ts_saved.tv_nsec);
                    curr_byte_rate = (bytes_received * 1000000000) / (time_delta);
                    debug_print("Time delta: %.09f\n", (double )(time_delta) / 1e9);
//                    printf("curr_byte_rate %d\n", curr_byte_rate);
                    ts_saved = ts_now;

                    /*                    New math
                     *
                     *					bytes_left = param_injection_rate * time_delta - curr_byte_rate * time_delta = (param_injection_rate - curr_byte_rate) / time_delta
                     *
                     *					packet_nominal_length = bytes_received / prev_data_packets;
                     *
                     *
                     *					fec_part_ratio = bytes_left / (PACKET_OVERHEAD + packet_nominal_length);
                     *
                     *					if (fec_part_ratio < 1) {
                     *						data_part_ratio = prev_data_packets / fec_part_ratio;
                     *						if (data_part_ratio >= MAX_PACKETS_PER_BLOCK) {
                     *							data_part_ratio = 1;
                     *							fec_part_ratio = 0;
                     *						} else {
                     *							packet_nominal_length = bytes_left - PACKET_OVERHEAD;
                     *							fec_part_ratio = 1;
                     *						}
                     *
                     *					} else if (fec_part_ratio > prev_data_packets) {
                     *						fec_part_ratio = 1;
                     *						data_part_ratio = 1;
                     *					} else {
                     *						data_part_ratio = prev_data_packets;
                     *
                     *					}
                     *
                     *
                     * 					param_injection_rate = ratio * curr_byte_rate
                     *
                     * 					ratio = (fec_part_ratio + data_part_ratio) / data_part_ratio
                     *
                     * 					param_injection_rate = ((fec_part_ratio + data_part_ratio) / data_part_ratio) * prev_data_packets * (PACKET_OVERHEAD + bytes_received / prev_data_packets) / time_delta
                     *
                     * 					param_injection_rate = ratio * (PACKET_OVERHEAD * prev_data_packets + bytes_received) / time_delta
                     *
                     *
                     *
                     *
                     * 					packet_payload_length = bytes_received / prev_data_packets;
                     * 					packet_nominal_length = packet_payload_length;
                     *
                     * 					(fec_part_ratio + data_part_ratio)/time_delta = prev_data_packets / time_delta;
                     *
                     param_injection_rate = (fec_part_ratio + data_part_ratio) * (PACKET_OVERHEAD + bytes_received / data_part_ratio) / time_delta;

                     fec_part_ratio + data_part_ratio = param_injection_rate * time_delta / (PACKET_OVERHEAD + bytes_received / prev_data_packets);

                     PACKET_OVERHEAD + bytes_received / prev_data_packets = param_injection_rate * time_delta / (fec_part_ratio + data_part_ratio)

                     packet_nominal_length = param_injection_rate * time_delta / (fec_part_ratio + data_part_ratio) - PACKET_OVERHEAD

                     Example:
                     time_delta = 0.0003
                     param_injection_rate = 2375000;
                     bytes_received = 6;
                     MAX_PACKETS_PER_BLOCK = 64
                     PACKET_OVERHEAD = 43
                     prev_data_packets = 1

                     fec_part_ratio + data_part_ratio = 	2375000 * 0.0003 / (43 + 6 / 1) = 14.54

                     Example:
                     time_delta = 0.0003
                     param_injection_rate = 2375000;
                     bytes_received = 600;
                     MAX_PACKETS_PER_BLOCK = 64
                     PACKET_OVERHEAD = 43
                     prev_data_packets = 1

                     fec_part_ratio + data_part_ratio = 1.11

                     fec_part_ratio + prev_data_packets = 1.11

                     fec_part_ratio = 0.11

                     (fec_part_ratio + prev_data_packets) * scale = MAX_PACKETS_PER_BLOCK

                     scale = MAX_PACKETS_PER_BLOCK / (fec_part_ratio + prev_data_packets)

                     fec_part_ratio_new = fec_part_ratio * scale = MAX_PACKETS_PER_BLOCK * fec_part_ratio / (fec_part_ratio + prev_data_packets) = 6

                     data_part_ratio_new = MAX_PACKETS_PER_BLOCK * prev_data_packets / (fec_part_ratio + prev_data_packets) = 57

                     packet_nominal_length = 2375000 * 0.0003 / (6 + 57) - 43 =

                     param_injection_rate = (6 + 57) * (43 + 10) / 0.0003 =

                     Example:
                     time_delta = 0.0003
                     param_injection_rate = 2375000;
                     bytes_received = 313;
                     MAX_PACKETS_PER_BLOCK = 64
                     PACKET_OVERHEAD = 43
                     prev_data_packets = 1

                     fec_part_ratio + data_part_ratio = 	2375000 * 0.0003 / (43 +  313/ 1) = 2


                     param_injection_rate = MAX_PACKETS_PER_BLOCK * (PACKET_OVERHEAD + bytes_received / data_part_ratio) / time_delta;

                     param_injection_rate * time_delta / MAX_PACKETS_PER_BLOCK = PACKET_OVERHEAD + bytes_received / data_part_ratio;

                     param_injection_rate * time_delta / MAX_PACKETS_PER_BLOCK - PACKET_OVERHEAD = bytes_received / data_part_ratio;

                     data_part_ratio = bytes_received / (param_injection_rate * time_delta / MAX_PACKETS_PER_BLOCK - PACKET_OVERHEAD);

                     packet_nominal_length = bytes_received / data_part_ratio;

                     fec_part_ratio = MAX_PACKETS_PER_BLOCK - data_part_ratio;

                     PACKET_OVERHEAD + bytes_received / data_part_ratio > 0
                     bytes_received / data_part_ratio > -PACKET_OVERHEAD

                     data_part_ratio > bytes_received / -PACKET_OVERHEAD
                     PACKET_OVERHEAD + bytes_received / data_part_ratio <= MAX_USER_PACKET_LENGTH

                     bytes_received / data_part_ratio <= MAX_USER_PACKET_LENGTH - PACKET_OVERHEAD

                     data_part_ratio => bytes_received / (MAX_USER_PACKET_LENGTH - PACKET_OVERHEAD)


                     bytes_received / data_part_ratio

                     data_part_ratio > 0
                     data_part_ratio <= 64

                     fec_part_ratio >= 0
                     fec_part_ratio <= 32

                     data_part_ratio + fec_part_ratio <= 64

                     data_part_ratio <= 64 - fec_part_ratio




                     Example:
                     time_delta = 0.0003
                     param_injection_rate = 2375000;
                     bytes_received = 6;
                     MAX_PACKETS_PER_BLOCK = 64
                     PACKET_OVERHEAD = 43

                     data_part_ratio = 6 / (2375000 * 0.0003 / 64 - 43) =


                     param_injection_rate = pkt_rate * PACKET_OVERHEAD + pkt_rate * packet_payload_length;

                     param_injection_rate = ratio * (pkt_rate * PACKET_OVERHEAD + curr_byte_rate);

                     pkt_rate = prev_data_packets * 1000000000 / time_delta;

                     ratio = param_injection_rate / (pkt_rate * PACKET_OVERHEAD + curr_byte_rate);

                     ratio = param_injection_rate /
                     ((prev_data_packets * PACKET_OVERHEAD * 1000000000) / time_delta + curr_byte_rate);


                     ratio = param_injection_rate / (prev_data_packets * PACKET_OVERHEAD / time_delta + bytes_received / time_delta);

                     ratio = param_injection_rate * time_delta / (prev_data_packets * PACKET_OVERHEAD + bytes_received);
                     ratio = (fec_part_ratio + data_part_ratio) / data_part_ratio;

                     ratio = (MAX_PACKETS_PER_BLOCK) / data_part_ratio;

                     data_part_ratio = MAX_PACKETS_PER_BLOCK / ratio;

                     fec_part_ratio = MAX_PACKETS_PER_BLOCK - MAX_PACKETS_PER_BLOCK / ratio;*/

                    /*                    uint64_t ratio = param_injection_rate * 1000 /
                     ((prev_data_packets * PACKET_OVERHEAD * 1000000000) / time_delta + curr_byte_rate);

                     int64_t fec_part_ratio, data_part_ratio;
                     if (ratio >= 2000) {
                     fec_part_ratio = 1;
                     data_part_ratio = 1;
                     } else if ((ratio > 1000) && (ratio < 2000)) {
                     data_part_ratio = MAX_PACKETS_PER_BLOCK * 1000 / ratio;
                     fec_part_ratio = MAX_PACKETS_PER_BLOCK - data_part_ratio;
                     simplify_ratio(&data_part_ratio, &fec_part_ratio);
                     }*/

                    /*formula to calculate rate limit is dependent on FEC parameters and packet length
                     * 	param_injection_rate/curr_byte_rate=(fec_part_ratio/data_part_ratio+1)*(PACKET_OVERHEAD/packet_payload_length + 1)
                     * then:
                     * 	packet_payload_length=(PACKET_OVERHEAD*curr_byte_rate*(fec_part_ratio/data_part_ratio+1))/(param_injection_rate-curr_byte_rate*(fec_part_ratio/data_part_ratio+1))
                     * and:
                     * 	fec_part_ratio/data_part_ratio=(param_injection_rate*packet_payload_length-curr_byte_rate*(packet_payload_length+PACKET_OVERHEAD))/(curr_byte_rate*(packet_payload_length+PACKET_OVERHEAD))
                     * 	*/
                    //starting with the most robust settings FEC=DATA=1
                    fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio = 1;
                    fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio = 1;
                    fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length =
                    MAX_USER_PACKET_LENGTH;
                    //checking if we can go with FEC=DATA=1
                    if (run_opts.injection_rate
                            * fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length
                            >= (curr_byte_rate
                                    * (PACKET_OVERHEAD
                                            + fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                            .packet_payload_length)
                                    * (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio
                                            / fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                            .data_part_ratio + 1))) {
                        //if so calculate actual packet payload length
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length =
                        (PACKET_OVERHEAD_LEN * curr_byte_rate
                                * (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio
                                        / fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                        .data_part_ratio + 1))
                        / (run_opts.injection_rate
                                - curr_byte_rate
                                * (fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                        .fec_part_ratio
                                        / fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                        .data_part_ratio + 1));
//            debug_print(
                        fprintf(stderr,
                                "FEC=DATA=1: tot bytes: %ld, ovh %ld, act_len %d, packet_payload_length %d, param_min_packet_length %ld, param_injection_rate %ld, curr_byte_rate %d, fec %d, data %d\n",
                                bytes_received,
                                PACKET_OVERHEAD_LEN,
                                last_payload_len,
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length,
                                run_min_packet_length, run_opts.injection_rate,
                                curr_byte_rate,
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio,
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio);
                    } else if (run_opts.injection_rate < curr_byte_rate) {
                        //since current bitrate is higher than maximum we will loose packets anyway, no point in adding any FEC packets
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio = 0;
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio = 1;
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length =
                        MAX_USER_PACKET_LENGTH;

                        debug_print(
                                "FEC= 1, DATA=%d: tot bytes: %ld, ovh %ld, act_len %d, packet_payload_length %d, param_min_packet_length %ld, param_injection_rate %ld, curr_byte_rate %d, fec %d, data %d\n",
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio,
                                bytes_received,
                                PACKET_OVERHEAD_LEN,
                                last_payload_len,
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length,
                                run_min_packet_length, run_opts.injection_rate,
                                curr_byte_rate,
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio,
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio);
                    } else {
                        //if not trying to get rough FEC and DATA ratios values
                        uint64_t fec_part_ratio = (run_opts.injection_rate
                                * (uint64_t) fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                .packet_payload_length
                                - (uint64_t) curr_byte_rate
                                * ((uint64_t) fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                        .packet_payload_length + PACKET_OVERHEAD));
                        uint64_t data_part_ratio = (uint64_t) curr_byte_rate
                        * ((uint64_t) fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                .packet_payload_length + PACKET_OVERHEAD_LEN);
//                        printf("packet_payload_length %d, curr_byte_rate %d, param_injection_rate %ld, fec_part_ratio %ld, data_part_ratio %ld\n",
//                                                		fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length,
//														curr_byte_rate, param_injection_rate,
//                        								fec_part_ratio, data_part_ratio);
                        //trying to scale FEC and DATA ratios based on MAX_PACKETS_PER_BLOCK and supplied FPS value
                        uint64_t scale = data_part_ratio + fec_part_ratio;
                        uint64_t max_packets_per_frame = curr_byte_rate
                        / (run_opts.frame_rate
                                * (fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                        .packet_payload_length + PACKET_OVERHEAD_LEN));
                        if ((MAX_PACKETS_PER_BLOCK < max_packets_per_frame) /*||
                                 ((param_injection_rate * fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio) <
                                 (curr_byte_rate *
                                 (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio + fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio)))*/)
                        scale /= MAX_PACKETS_PER_BLOCK;
                        else
                        scale /= max_packets_per_frame;
                        //scaling down FEC and DATA ratios to fit in MAX_PACKETS_PER_BLOCK and FPS margins
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio =
                        fec_part_ratio / scale;
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio =
                        data_part_ratio / scale;
                        if (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio
                                > fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio)
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio = fifo
                        .fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio;
                        //calculating new packet payload length based on scaled FEC and DATA ratios
                        int64_t packet_payload_length;
                        while (1) {
                            packet_payload_length = (int64_t) (PACKET_OVERHEAD_LEN
                                    * curr_byte_rate
                                    * (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio
                                            + fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                            .data_part_ratio))
                            / (int64_t) (run_opts.injection_rate
                                    * fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                    .data_part_ratio
                                    - curr_byte_rate
                                    * (fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                            .fec_part_ratio
                                            + fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                            .data_part_ratio));
                            if ((packet_payload_length <= MAX_USER_PACKET_LENGTH)
                                    && (packet_payload_length > 0)) {
                                break;
                            } else if ((fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                            .fec_part_ratio
                                            + fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio)
                                    < MAX_PACKETS_PER_BLOCK) {
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio++;
                            } else if (fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                    .fec_part_ratio > 1) {
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio--;
                            } else {
                                packet_payload_length = MAX_USER_PACKET_LENGTH;
                                break;
                            }
                        }
                        if (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio
                                == 0) {
                            debug_print("FEC=0\n");
                        }
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length =
                        packet_payload_length;
//            debug_print(
                        fprintf(stderr,
                                ">>>packet_payload_length %d, curr_byte_rate %d, param_injection_rate %ld, fec_part_ratio %d, data_part_ratio %d\n",
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length,
                                curr_byte_rate, run_opts.injection_rate,
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio,
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio);

                    }
#endif
/*                    if (fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                            .packet_payload_length
                            < (sizeof(ps->payload.sPayload.len) + 1)) {
                        debug_print(
                                "packet_payload_length=%d, bare len: %d\n",
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                        .packet_payload_length,
                                last_payload_len);
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                .packet_payload_length = last_payload_len
                                + sizeof(ps->payload.sPayload.len);
                        run_min_packet_length = 0;
                    } else {
                        run_min_packet_length =
                                fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                        .packet_payload_length
                                        - sizeof(ps->payload.sPayload.len);
                    }
                    if (fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                            .packet_payload_length > MAX_USER_PACKET_LENGTH) {
                        printf("Wrong packet length %d, rate %d, FEC %d, data %d\n",
                               fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                       .packet_payload_length,
                               curr_byte_rate,
                               fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                       .fec_part_ratio,
                               fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                       .data_part_ratio);
                        exit(1);
                    }*/
//                    debug_print( ">>>>>Packet# %d, Result rate %ld Bytes/s vs param_injection_rate %ld Bytes/s\n", pcnt,
//							((PACKET_OVERHEAD + fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length) *
//							(fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio + fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio) * curr_byte_rate) /
//							(fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length * fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio),
//							param_injection_rate);
//                    printf("Final packet_payload_length %d\n", fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length);

                    run_packet_length = fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length;
//                    run_packet_length =
//                            fifo.fifo_array[i].pb_overlay[used_rx_ovl]
//                                    .packet_payload_length
//                                    - sizeof(ps->payload.sPayload.len);
                    if(fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio > 0) {
                        run_min_packet_length = run_packet_length;
                    } else {
                        run_min_packet_length = 0;
                    }
//          debug_print(
                    fprintf(stderr,
                            "Final packet_payload_length %d, param_min_packet_length: %ld, tot bytes: %ld\n",
                            fifo.fifo_array[i].pb_overlay[used_rx_ovl]
                                    .packet_payload_length,
                            run_min_packet_length, bytes_received);
                    bytes_received = 0;
                } else {
//                	printf("not enough packets\n");
                    //not enough packets to fill the block moving to the next packet
                    fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data++;
                }

            }
            //excluding already processed FIFO from the ready mask
            nfds_mask &= ~(1 << j);
            j = (j + 1) % nfds;
        }
        //statistics print
        if (pcnt % 128 == 0) {
//            printf("data packets received: %d, rate: %d bytes/s\r", pcnt,
//                    curr_byte_rate);
        }

    }

    printf("Exiting the program\n");

    return (0);
}
