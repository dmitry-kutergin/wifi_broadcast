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

/* this is the template radiotap header we send packets out with */
#if 0
static u8 u8aRadiotapHeader[] = { 0x00, 0x00, // <-- radiotap version
        0x0c, 0x00, // <- radiotap header length
        0x04, 0x80, 0x00, 0x00, // <-- radiotap present flags
//	0x18, // datarate 12Mbit
//	0x24, // datarate 18Mbit
//	0x30, // datarate 24Mbit
//	0x48, // datarate 36Mbit
        0x60, // datarate 48Mbit
        0x0, 0x18, 0x00 };

/* Penumbra IEEE80211 header */

//the last byte of the mac address is recycled as a port number
#define SRC_MAC_LASTBYTE 15
#define DST_MAC_LASTBYTE 21

static u8 u8aIeeeHeader[] = { 0x08, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x13, 0x22, 0x33, 0x44, 0x55, 0x66, 0x13, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x10, 0x86 };

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
	} IeeeHeader ;
    wifi_packet_header_t wifi_hdr;
    payload_header_t payload_hdr;
    uint8_t payload[MAX_USER_PACKET_LENGTH];
}__attribute__((packed));

//size of all aux headers in transmitted packet
#define PACKET_OVERHEAD (sizeof(struct tRadiotapHeader) + sizeof(struct ieee80211_hdr_3addr) + sizeof(wifi_packet_header_t) + sizeof(payload_header_t))
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
        uint8_t fec_part_ratio;
        //variable number of DATA packets
        uint8_t data_part_ratio;
        //index of the currently filled packet in the reception thread
        uint8_t curr_pb_data;
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
struct timespec last_time = {0};

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
        {   { "port",              'p', "port",   0,
                    "Port number 0-255 (default 0)" },
            { "block_packets", 	   'b', "count",  0,
                    "Number of data packets in a block (default 8). Needs to match with rx" },
            { "block_fec_packets", 'r', "count",  0,
                    "Number of FEC packets per block (default 4). Needs to match with rx" },
            { "packet_bytes",      'f', "bytes",  0,
                    "Number of bytes per packet (default 1450. max 1450). This is also the FEC block size. Needs to match with rx" },
            { "min_bytes",         'm', "bytes",  0,
                    "Minimum number of bytes per frame (default 0)" },
            { "stream",            's', "stream", 0,
                    "If <stream> is > 1 then the parameter changes \"tx\" input from stdin to named FIFOs. Each fifo transports a stream over a different port (starting at -p port and incrementing). FIFO names are \"/tmp/fifo%d\". (default 1)" },
            { "frequency",         'x',  "value", 0,
                    "How often is a block transmitted (default 1)" },
            { "rate",              'i', "Mbps",   0,
                    "Mbits/s transmission rate" },
            { "duplicate",         'd',    0,     0,
                    "Enable packet duplication through multiple interfaces, otherwise load sharing is performed" },
            { "fps",               'a',  "fps",   0,
                    "Expected video FPS for optimal FEC/frame size calculation" },
#ifdef INTERLEAVED
            { "interleaver",       't',    0,     0,
                    "Enable interleaver" },
#endif
            { "wlan",              'w', "list",   0,
                    "WLAN list" },
            {   0 } };


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
        uint8_t block_size_fec, uint8_t port, uint16_t packet_payload_length, uint8_t inj_rate)
{
    int i;
    const uint8_t addr1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t addr2[] = {0x02, 'w', 'i', 'f', 'i', 0};
    const uint8_t addr3[] = {0x22, 'w', 'i', 'f', 'i', 0};

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
#ifndef BLOCK_TX
            //setting currently transmitting buffer index in processing thread to 0
            fifo->fifo_array[i].pb_overlay[k].tx_pb_data = 0;
#endif
            //initializing DATA packet buffer array pointer at the beginning of shared medium
            fifo->fifo_array[i].pb_overlay[k].pbl_data =
                    fifo->fifo_array[i].pb_overlay[k].pbl_placeholder;
            //initializing FEC packet buffer array pointer right after DATA packet buffer array
            fifo->fifo_array[i].pb_overlay[k].pbl_fec =
                    fifo->fifo_array[i].pb_overlay[k].pbl_placeholder + block_size_data;
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
                struct pkt_struct_t * ps =
                        (struct pkt_struct_t *) fifo->fifo_array[i].pb_overlay[k].pbl_placeholder[j].data;

                ps->RadiotapHeader.sRadiotapHeader.radiotap_header.it_version = 0;
                ps->RadiotapHeader.sRadiotapHeader.radiotap_header.it_pad = 0;
                ps->RadiotapHeader.sRadiotapHeader.radiotap_header.it_len = sizeof(struct tRadiotapHeader);
                ps->RadiotapHeader.sRadiotapHeader.radiotap_header.it_present =
                		(1 << IEEE80211_RADIOTAP_TX_FLAGS) | (1 << IEEE80211_RADIOTAP_RATE);
                ps->RadiotapHeader.sRadiotapHeader.DataRate = inj_rate *2;
                ps->RadiotapHeader.sRadiotapHeader.TxFlags = IEEE80211_RADIOTAP_F_TX_NOACK | IEEE80211_RADIOTAP_F_TX_SEQ;

                //initializing radio tap header
                /*memcpy(ps->RadiotapHeader, u8aRadiotapHeader,
                        sizeof(u8aRadiotapHeader));*/
                //initializing IEEE header
//                memcpy(ps->IeeeHeader, u8aIeeeHeader, sizeof(u8aIeeeHeader));
                ps->IeeeHeader.sIeeeHeader.frame_control = IEEE80211_FCTL_TODS | IEEE80211_FTYPE_DATA;
				ps->IeeeHeader.sIeeeHeader.duration_id = 0;

				memmove(ps->IeeeHeader.sIeeeHeader.addr1, addr1, ETH_ALEN);
				memmove(ps->IeeeHeader.sIeeeHeader.addr2, addr2, ETH_ALEN);
				memmove(ps->IeeeHeader.sIeeeHeader.addr3, addr3, ETH_ALEN);
				ps->IeeeHeader.sIeeeHeader.addr2[5] = i + port;
				ps->IeeeHeader.sIeeeHeader.addr3[5] = i + port;
				ps->IeeeHeader.sIeeeHeader.seq_ctrl=(IEEE80211_SCTL_SEQ & (0x861 << 4)) | (IEEE80211_SCTL_FRAG & 0x0);

//                set_port_no(ps->RadiotapHeader, i + port);
                //assigning payload buffer pointers to packet structure payload portions
                fifo->fifo_array[i].pb_overlay[k].data_blocks[j] = ps->payload;
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
        if (fifo->ppcap_arr[i])
            pcap_close(fifo->ppcap_arr[i]);
    }
    //freeing PCAP handles array
    free(fifo->ppcap_arr);
    fifo->num_pcap = 0;
    //deallocating all FIFOs array elements
    for (i = 0; i < fifo->fifo_num; ++i) {
        //closing file descriptor for opened FIFOs
        if (fifo->fifo_array[i].fd && fifo->fifo_array[i].fd != STDIN_FILENO)
            close(fifo->fifo_array[i].fd);
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
    if (fifo)
        fifo_gc(fifo);
    printf("%s\n", __PRETTY_FUNCTION__);
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
#include <stdio.h>
#include <ctype.h>
#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 32
#endif
void hexdump(void *mem, unsigned int len)
{
        unsigned int i, j;

        for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
        {
                /* print offset */
                if(i % HEXDUMP_COLS == 0)
                {
                        printf("0x%06x: ", i);
                }

                /* print hex data */
                if(i < len)
                {
                        printf("%02x ", 0xFF & ((char*)mem)[i]);
                }
                else /* end of block, just aligning for ASCII dump */
                {
                        printf("   ");
                }

                /* print ASCII dump */
                if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
                {
                        for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
                        {
                                if(j >= len) /* end of block, not really printing */
                                {
                                        putchar(' ');
                                }
                                else if(isprint(((char*)mem)[j])) /* printable char */
                                {
                                        putchar(0xFF & ((char*)mem)[j]);
                                }
                                else /* other char */
                                {
                                        putchar('.');
                                }
                        }
                        putchar('\n');
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
//    printf("blknum %d, blknum_old %d, pktnum %d, is_fec %d\n", blknum, blknum_old, pktnum, is_fec);
    ps->wifi_hdr.block_number = blknum;
    ps->wifi_hdr.packet_number = pktnum++;
    ps->wifi_hdr.fec_taint = is_fec;
    if (blknum != blknum_old)
        pktnum = 0;
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
        if (!fifo->duplicated && (curr_ppcap != i))
            continue;
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
        if(is_fec)
        	printf("FEC tx\n");
        else
        	printf("DATA tx\n");
        hexdump(data, PACKET_OVERHEAD);
        hexdump(&ps->wifi_hdr, sizeof(ps->wifi_hdr));
        hexdump(data + PACKET_OVERHEAD, ps->payload_hdr.nominal_packet_length);
#else

//        fprintf(stderr, ">>>>>>>Packet# %d, Block# %d, packet index %ld, plen %d\n", pktnum, blknum, pktnum_all, plen);
        write(STDOUT_FILENO, data, plen);
#endif
        if(!is_fec)
			pktnum_all++;

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
        uint16_t blknum)
{
    struct fifo_arr_t * curr_fifo = &fifo->fifo_array[curr_fifo_index];
    int i;
#ifndef BLOCK_TX
//    printf("pb_process_block tx_pb_data %d, curr_pb_data %d\n",
//    		curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].tx_pb_data, curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].curr_pb_data);
    //transmit remaining ready data packets if any
    while (curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].tx_pb_data < curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].curr_pb_data) {
//        printf("pb_process_block TX pkt blknum %d\n", blknum);
    	pb_transmit_packet(fifo, curr_fifo_index,
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].pbl_data[curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].tx_pb_data++].data,
                blknum, 0);
    }
#endif
    //if number of FEC packets is greater than 0
    if (curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].fec_part_ratio) {
        //encode FEC data
        fec_encode(
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].packet_payload_length,
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].data_blocks,
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].data_part_ratio,
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].data_blocks + curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].data_part_ratio,
                curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].fec_part_ratio);
    }
#ifndef BLOCK_TX
    //transmit all FEC packets
    for (i = 0; i < curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].fec_part_ratio;
            ++i) {
    	packet_buffer_t *pb =
    			&curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].pbl_data[curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].data_part_ratio + i];
    	struct pkt_struct_t * ps = (struct pkt_struct_t *) pb->data;
    	//filling packet header data
		//actual data length
		ps->payload_hdr.actual_length =
				curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].packet_payload_length;
		//current block packet length
		ps->payload_hdr.nominal_packet_length =
				curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].packet_payload_length;
		//current FEC ratio
		ps->payload_hdr.num_data_blocks =
				curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].data_part_ratio;
		//current DATA ratio
		ps->payload_hdr.num_fecs_blocks =
				curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].fec_part_ratio;

        pb_transmit_packet(fifo, curr_fifo_index,
                pb->data,
                blknum, 1);
    }
    curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].tx_pb_data = 0;
#endif
    //current packet index reset
    curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].curr_pb_data = 0;
    //reset the length back
    for (i = 0;
            i < curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].data_part_ratio;
            ++i) {
        curr_fifo->pb_overlay[curr_fifo->curr_proc_overlay].pbl_data[i].len = 0;

    }
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
    if (signum == SIGALRM) {
        struct timespec now_time;
        clock_gettime(CLOCK_MONOTONIC, &now_time);
        fprintf(stderr, "---Data rate: %.3f KBits/s---\n"/*\033[1A"*/,
                ((float)bytes_sent * 8 / 1000) /
				((float)now_time.tv_sec + (float)now_time.tv_nsec/10e9 - (float)last_time.tv_sec - (float)last_time.tv_nsec/10e9));
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
            //if processing thread overlay index reached reception thread overlay index move to the next FIFO
            if (pfifo->fifo_array[i].curr_rx_overlay == pfifo->fifo_array[i].curr_proc_overlay) {
#ifndef BLOCK_TX
//                printf("Tx from FIFO %d, curr_rx_overlay %d, curr_proc_overlay %d\n", i, pfifo->fifo_array[i].curr_rx_overlay, pfifo->fifo_array[i].curr_proc_overlay);
                //check if new data packets were read, if so transmit them immediately to reduce latency and tx burstiness (make more uniform transmission rate)
                uint8_t cpo_val = pfifo->fifo_array[i].curr_proc_overlay;
//                printf("tx_pb_data %d, curr_pb_data %d\n",
//                		pfifo->fifo_array[i].pb_overlay[cpo_val].tx_pb_data, pfifo->fifo_array[i].pb_overlay[cpo_val].curr_pb_data);
                while (pfifo->fifo_array[i].pb_overlay[cpo_val].tx_pb_data < pfifo->fifo_array[i].pb_overlay[cpo_val].curr_pb_data) {
//                	printf("TX blknum %d\n", blknum);
                    pb_transmit_packet(pfifo, i,
                            pfifo->fifo_array[i].pb_overlay[cpo_val].pbl_data[pfifo->fifo_array[i].pb_overlay[cpo_val].tx_pb_data++].data,
                            blknum, 0);
                }
#endif
                sched_yield();
                continue;
            }
            //process packets otherwise
            pb_process_block(pfifo, i, blknum);
            blknum++;
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
//greatest common divider helper function RFU
long gcd(long a, long b)
{
    if (a == 0)
        return b;
    else if (b == 0)
        return a;

    if (a < b)
        return gcd(a, b % a);
    else
        return gcd(b, a % b);
}
// Options parser
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	/* Get the input argument from argp_parse, which we
	 know is a pointer to our opts structure. */
	struct opts_t *opts = (struct opts_t *) state->input;


	switch (key) {
	case 'r': // retransmissions
		opts->fec_packets_per_block = arg ? atoi(arg) : 1;
		break;
	case 'f': // MTU
		opts->packet_length = arg ? atoi(arg) : MAX_USER_PACKET_LENGTH;
		if (opts->packet_length > MAX_USER_PACKET_LENGTH) {
			printf(
					"Packet length is limited to %d bytes (you requested %d bytes)\n",
					MAX_USER_PACKET_LENGTH, (int)opts->packet_length);
			argp_usage (state);
		}
		break;
	case 'p': //port
		opts->port = arg ? atoi(arg) : 0;
		break;
	case 'b': //retransmission block size
		opts->data_packets_per_block = arg ? atoi(arg) : 1;
		break;
	case 'm': //minimum packet length
		opts->min_packet_length = arg ? atoi(arg) : 0;
		break;
	case 's': //how many streams (fifos) do we have in parallel
		opts->fifo_count = arg ? atoi(arg) : 1;
		break;
	case 'x': //how often is a block transmitted
		opts->transmission_count = arg ? atoi(arg) : 1;
		break;
	case 'i': //injection rate
		opts->injection_rate = arg ? atoi(arg) : 24;
		break;
	case 'a': //frame rate
		opts->frame_rate = arg ? atoi(arg) : 80;
		break;
#ifdef INTERLEAVED
	case 't': //interleaved transmission
		opts->interleaved = 1;
		break;
#endif
	case 'd': //duplicated transmission
		opts->duplicated = 1;
		break;
	case 'w': //wlan list
	    if (arg){
	        if (strlen(opts->wlan_list) + strlen(arg) < WLAN_BUFFER_SIZE){
                if (opts->wlan_list[0]){
                    strncat(opts->wlan_list, ";", 1);
                }
                strncat(opts->wlan_list, arg, 10);
	        }
	    }
		break;
	case ARGP_KEY_END:
#ifndef TEST_EN
		if(!opts->wlan_list){
			argp_usage (state);
			break;
		}
#endif
		if (opts->min_packet_length > opts->packet_length) {
			fprintf(stderr,
					"Your minimum packet length is higher that your maximum packet length (%d > %d)\n",
					(int)opts->min_packet_length, (int)opts->packet_length);
			opts->min_packet_length = opts->packet_length;
			argp_usage (state);
			break;
		}
	    if (opts->fifo_count > MAX_FIFOS) {
	        fprintf(stderr,
	                "The maximum number of streams (FIFOS) is %d (you requested %d)\n",
	                MAX_FIFOS, opts->fifo_count);
	        argp_usage (state);
	        break;
	    }

	    if (opts->data_packets_per_block > MAX_DATA_OR_FEC_PACKETS_PER_BLOCK || opts->fec_packets_per_block
	            > MAX_DATA_OR_FEC_PACKETS_PER_BLOCK) {
	        fprintf(stderr,
	                "Data and FEC packets per block are limited to %d (you requested %d data, %d FEC)\n",
	                MAX_DATA_OR_FEC_PACKETS_PER_BLOCK, opts->data_packets_per_block,
					opts->fec_packets_per_block);
	        argp_usage (state);
	        break;
	    }

	    if ((opts->frame_rate < 15) && (opts->frame_rate > 200)) {
	        fprintf(stderr,
	                "Frame rate supplied %d is outside limits: [15, 200] \n",
					opts->frame_rate);
	        argp_usage (state);
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
    struct opts_t run_opts = { 0 , 4, MAX_USER_PACKET_LENGTH, 8, 0, 1, 1, 24, 80, 0, 0, 0};
    //processing command line arguments
    argp_parse(&argp, argc, argv, 0, 0, &run_opts);

    timer_t tp_timer;
    //creating statistics timer
    if (timer_create(CLOCK_MONOTONIC, NULL, &tp_timer) == -1) {
        perror("Failed to create timer\n");
        return 1;
    }
    //garbage collector push
    on_exit(gc_timer, &tp_timer);
    //mapping all available signals to our signal handler
    for (i = 1; i <= SIGPWR; ++i) {
        if (i != SIGKILL)
            signal(i, sig_handler);
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
    		run_opts.fec_packets_per_block, run_opts.port, run_opts.packet_length, run_opts.injection_rate);
    //garbage collector push
    on_exit(gc_fifo, &fifo);
    //maximum injection rate
    run_opts.injection_rate = run_opts.injection_rate * 10e6 / 8;

	if (run_opts.injection_rate > INJ_RATE_MAX)
		run_opts.injection_rate = INJ_RATE_MAX;
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
	char *arg_value = strtok (run_opts.wlan_list, separator);
	int wlan_list_count =0;
	while (arg_value != NULL) {
	    wlan_list_count++;
		arg_value = strtok (NULL, separator);
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
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fifo.fifo_array[i].fd, &eearr[i]) == -1) {
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
    if (pthread_attr_setinheritsched(&pattr, PTHREAD_EXPLICIT_SCHED) && pthread_attr_setschedpolicy(
                &pattr, SCHED_OTHER)
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

            packet_buffer_t *pb =
                    &fifo.fifo_array[i].pb_overlay[used_rx_ovl].pbl_data[fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data];

            //if the buffer is fresh we add a payload header
//			if(pb->len == 0) {
//                pb->len += sizeof(payload_header_t); //make space for a length field (will be filled later)
//			}

            //read the data
            struct pkt_struct_t * ps = (struct pkt_struct_t *) pb->data;
            int inl = read(fifo.fifo_array[i].fd, ps->payload + pb->len,
            		run_opts.packet_length - pb->len);
            if ((inl < 0) || (inl > (int)(run_opts.packet_length - pb->len))) {
                perror("reading stdin");
                return 1;
            }
//            printf("Read bytes %d, combined bytes: %d\n", inl, pb->len);
            if (inl == 0) {
                //EOF
                fprintf(stderr,
                        "Warning: Lost connection to fifo %d. Please make sure that a data source is connected\n",
                        i);
                usleep(1e5);
                continue;
            }

            pb->len += inl;

            //check if we read enough data to move tothe next packet
            if (pb->len >= run_opts.min_packet_length) {
//                payload_header_t *ph = (payload_header_t*)pb->data;
//                ph->data_length = pb->len - sizeof(payload_header_t); //write the length into the packet. this is needed since with fec we cannot use the wifi packet lentgh anymore. We could also set the user payload to a fixed size but this would introduce additional latency since tx would need to wait until that amount of data has been received
                //RX statistics counter

                bytes_received += pb->len;

                //filling packet header data
                //actual data length
                ps->payload_hdr.actual_length = pb->len;
                //current block packet length
                ps->payload_hdr.nominal_packet_length =
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length;
                //current FEC ratio
                ps->payload_hdr.num_data_blocks =
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio;
                //current DATA ratio
                ps->payload_hdr.num_fecs_blocks =
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio;
                //statistics packet count
                pcnt++;
//                printf("Bytes received combined %d, actual_length %d, nominal_packet_length %d, num_data_blocks %d, num_fecs_blocks %d, pcnt %d\n",
//                		bytes_received, ps->payload_hdr.actual_length, ps->payload_hdr.nominal_packet_length, ps->payload_hdr.num_data_blocks, ps->payload_hdr.num_fecs_blocks, pcnt);
                //check if this block is finished
                if (fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data == fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio
                        - 1) {

                	fifo.fifo_array[i].pb_overlay[used_rx_ovl].curr_pb_data++;
                	//moving to the next overlay
                    fifo.fifo_array[i].curr_rx_overlay =
                            (fifo.fifo_array[i].curr_rx_overlay + 1) % OVERLAY_NUM;

                    used_rx_ovl = fifo.fifo_array[i].curr_rx_overlay;
                    //generating FEC and DATA ratios and packet payload size for the next block (overlay)
                    struct timespec ts_now;
                    clock_gettime(CLOCK_MONOTONIC, &ts_now);
                    //getting previous block data rate
                    curr_byte_rate =
                            (bytes_received * 1e9) / ((ts_now.tv_sec * 1e9 + ts_now.tv_nsec)
                                                      - (ts_saved.tv_sec * 1e9 + ts_saved.tv_nsec));
//                    printf("curr_byte_rate %d\n", curr_byte_rate);
                    ts_saved = ts_now;
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
                    if (run_opts.injection_rate * fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length >=
                    		(curr_byte_rate * (PACKET_OVERHEAD + fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length)
                            * (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio / fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio + 1))) {
                        //if so calculate actual packet payload length
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length =
                                (PACKET_OVERHEAD * curr_byte_rate
                                 * (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio / fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio + 1))
                                / (run_opts.injection_rate - curr_byte_rate
                                        * (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio / fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio + 1));

//                        fprintf(stderr, "FEC=DATA=1: ovh %ld, packet_payload_length %d, param_injection_rate %ld, curr_byte_rate %d, fec %d, data %d\n",PACKET_OVERHEAD,
//                        		fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length, param_injection_rate, curr_byte_rate,
//								fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio, fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio);
                    } else if (run_opts.injection_rate < curr_byte_rate) {
                    	fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio = 1;
                    	fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio = MAX_PACKETS_PER_BLOCK - fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio;
                    	fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length =
                    	                            MAX_USER_PACKET_LENGTH;
                    } else {
                        //if not trying to get rough FEC and DATA ratios values
                        uint64_t fec_part_ratio =
                                (run_opts.injection_rate * (uint64_t)fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length - (uint64_t)curr_byte_rate
                                        * ((uint64_t)fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length + PACKET_OVERHEAD));
                        uint64_t data_part_ratio =
                        		(uint64_t)curr_byte_rate * ((uint64_t)fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length
                                        + PACKET_OVERHEAD);
//                        printf("packet_payload_length %d, curr_byte_rate %d, param_injection_rate %ld, fec_part_ratio %ld, data_part_ratio %ld\n",
//                                                		fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length,
//														curr_byte_rate, param_injection_rate,
//                        								fec_part_ratio, data_part_ratio);
                        //trying to scale FEC and DATA ratios based on MAX_PACKETS_PER_BLOCK and supplied FPS value
                        uint64_t scale =
                                data_part_ratio + fec_part_ratio;
                        uint64_t max_packets_per_frame =
                                curr_byte_rate / (run_opts.frame_rate
                                        * (fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length + PACKET_OVERHEAD));
                        if ((MAX_PACKETS_PER_BLOCK < max_packets_per_frame) /*||
                        		((param_injection_rate * fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio) <
                        				(curr_byte_rate *
										(fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio + fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio)))*/)
                            scale /= MAX_PACKETS_PER_BLOCK;
                        else
                            scale /= max_packets_per_frame;
                        //scaling down FEC and DATA ratios to fit in MAX_PACKETS_PER_BLOCK and FPS margins
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio = fec_part_ratio / scale;
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio = data_part_ratio / scale;
                        if(fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio > fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio)
                        	fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio = fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio;
                        //calculating new packet payload length based on scaled FEC and DATA ratios
                        int64_t packet_payload_length;
                        while(1){
                        	packet_payload_length =
                                (int64_t)(PACKET_OVERHEAD * curr_byte_rate *
                                		(fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio + fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio)) /
								(int64_t)(run_opts.injection_rate * fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio - curr_byte_rate *
                                		(fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio + fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio));
                        	if((packet_payload_length <= MAX_USER_PACKET_LENGTH) && (packet_payload_length > 0)){
                        		break;
                        	} else if ((fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio + fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio) < MAX_PACKETS_PER_BLOCK) {
                        		fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio++;
                        	} else if (fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio > 1) {
                        		fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio--;
                        	} else {
                        		packet_payload_length = MAX_USER_PACKET_LENGTH;
                        		break;
                        	}
                        }
                        fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length = packet_payload_length;
//                        fprintf(stderr, ">>>packet_payload_length %d, curr_byte_rate %d, param_injection_rate %ld, fec_part_ratio %d, data_part_ratio %d\n",
//                        		fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length,
//								curr_byte_rate, param_injection_rate,
//								fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio,
//								fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio);

                    }
                    if(fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length == 0) {
                    	fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length = ps->payload_hdr.actual_length;
                    }
                    if(fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length > MAX_USER_PACKET_LENGTH) {
                    	printf("Wrong packet length %d, rate %d, FEC %d, data %d\n", fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length,
                    			curr_byte_rate,
								fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio,
								fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio);
                    	exit(1);
                    }
//                    fprintf(stderr, ">>>>>Packet# %d, Result rate %ld Bytes/s vs param_injection_rate %ld Bytes/s\n", pcnt,
//							((PACKET_OVERHEAD + fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length) *
//							(fifo.fifo_array[i].pb_overlay[used_rx_ovl].fec_part_ratio + fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio) * curr_byte_rate) /
//							(fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length * fifo.fifo_array[i].pb_overlay[used_rx_ovl].data_part_ratio),
//							param_injection_rate);
//                    printf("Final packet_payload_length %d\n", fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length);
                    run_opts.packet_length = fifo.fifo_array[i].pb_overlay[used_rx_ovl].packet_payload_length;
                    run_opts.min_packet_length = run_opts.packet_length;
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
