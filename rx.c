// (c)2015 befinitiv,
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

#include "fec.h"

#include "lib.h"
#include "wifibroadcast.h"
#include "radiotap.h"
#include <sys/epoll.h>
#include <pthread.h>

#define DEBUG 0
#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

// this is where we store a summary of the
// information from the radiotap header

typedef struct {
    int m_nChannel;
    int m_nChannelFlags;
    int m_nRate;
    int m_nAntenna;
    int m_nRadiotapFlags;
}__attribute__((packed)) PENUMBRA_RADIOTAP_DATA;

typedef struct {
    pcap_t *ppcap;
    int selectable_fd;
    int n80211HeaderLength;
} monitor_interface_t;

//Rx packet structure
struct pkt_struct_rx_t {
    wifi_packet_header_t wifi_hdr;
    payload_header_t payload_hdr;
    uint8_t payload[MAX_USER_PACKET_LENGTH];
}__attribute__((packed));
#define MAX_BLOCKS 8
//Packet buffer structure
struct pkt_buff_t {
    volatile uint16_t rx_idx;
    volatile uint16_t tx_idx;
    struct packets_t {
        uint16_t read_pkt_len;
        struct pkt_struct_rx_t data;
    }__attribute__((packed)) * packets;
    uint16_t pkt_num;
};
//Data structure for RX block data
typedef struct {
    int block_num;
    int curr_pkt_num;
    int data_pkts_cnt;
    int fec_pkts_cnt;
    payload_header_t payload_hdr;
    packet_buffer_t *packet_buffer_list;
} block_buffer_t;
//Storage for an array of RX blocks
typedef struct {
    block_buffer_t * blk_buffer;
    uint8_t blk_num;
    struct pkt_buff_t pkt_buffer;
} rx_data_t;

int flagHelp = 0;
int param_port = 0;
int param_data_packets_per_block = 8;
int param_fec_packets_per_block = 4;
int param_block_buffers = 2;
int param_packet_length = MAX_USER_PACKET_LENGTH;
wifibroadcast_rx_status_t *rx_status = NULL;

void usage(void)
{
    printf(
            "(c)2015 befinitiv, 2017 dkutergin. Licensed under GPL2\n"
                    "\n"
                    "Usage: rx [options] <interfaces>\n\nOptions\n"
                    "-p <port>   Port number 0-255 (default 0)\n"
                    "-b <count>  Number of data packets in a block (default 8). Needs to match with tx.\n"
                    "-r <count>  Number of FEC packets per block (default 4). Needs to match with tx.\n"
                    "-f <bytes>  Number of bytes per packet (default %d. max %d). This is also the FEC block size. Needs to match with tx\n"
                    "-d <blocks> Number of transmissions blocks that are buffered (default 1). This is needed in case of diversity if one\n"
                    "            adapter delivers data faster than the other. Note that this increases latency\n"
                    "\n"
                    "Example:\n"
                    "  rx -b 8 -r 4 -f 1024 wlan0 | cat /dev/null  (receive raw packets on wlan0 and throw away payload to /dev/null)\n"
                    "\n",
            MAX_USER_PACKET_LENGTH, MAX_USER_PACKET_LENGTH);
    exit(1);
}
//RX data garbage collector
static void gc_rx_data(int status, void * arg)
{
    if (arg) {
        rx_data_t * prx_data = (rx_data_t *) arg;
        uint8_t i;
        for (i = 0; i < prx_data->blk_num; ++i) {
            free(prx_data->blk_buffer[i].packet_buffer_list);
        }
        free(prx_data->blk_buffer);
        free(prx_data->pkt_buffer.packets);
    }
    printf("%s\n", __PRETTY_FUNCTION__);
}
//mapped memory garbage collector
void gc_mmap(int status, void * arg)
{
    if (arg) {
        munmap(arg, sizeof(wifibroadcast_rx_status_t));
    }
    printf("%s\n", __PRETTY_FUNCTION__);
}
//open a PCAP socket on supplied interface
void open_and_configure_interface(const char *name, int port,
        monitor_interface_t *interface)
{
    struct bpf_program bpfprogram;
    char szProgram[512];
    char szErrbuf[PCAP_ERRBUF_SIZE];
    // open the interface in pcap
    szErrbuf[0] = '\0';
    interface->ppcap = pcap_open_live(name, 2048, 1, -1, szErrbuf);
    if (interface->ppcap == NULL) {
//		fprintf(stderr, "\033[1;1HUnable to open %s: %s\n", name, szErrbuf);
        fprintf(stderr, "Unable to open %s: %s\n", name, szErrbuf);
        exit(1);
    }
    //PCAP handle GC assignment
    on_exit(gc_pcap, interface->ppcap);
    if (pcap_setnonblock(interface->ppcap, 1, szErrbuf) < 0) {
        fprintf(stderr, "Error setting %s to nonblocking mode: %s\n", name,
                szErrbuf);
    }
    //geting link level properties of the interface
    int nLinkEncap = pcap_datalink(interface->ppcap);
    //setting a filter string for ethernet MAC address field to rx packets with required port
    switch (nLinkEncap) {
        case DLT_PRISM_HEADER:
            //fprintf(stderr, "DLT_PRISM_HEADER Encap\n");
            interface->n80211HeaderLength = 0x20; // ieee80211 comes after this
            sprintf(szProgram,
                    "radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x",
                    port);
            break;

        case DLT_IEEE802_11_RADIO:
            //fprintf(stderr, "DLT_IEEE802_11_RADIO Encap\n");
            interface->n80211HeaderLength = 0x18; // ieee80211 comes after this
            sprintf(szProgram,
                    "ether[0x0a:4]==0x13223344 && ether[0x0e:2] == 0x55%.2x",
                    port);
            break;

        default:
            fprintf(stderr, "!!! unknown encapsulation on %s !\n", name);
            exit(1);

    }
    //preparing BPF filter to filter only required port number
    if (pcap_compile(interface->ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
        puts(szProgram);
        puts(pcap_geterr(interface->ppcap));
        exit(1);
    } else {
        if (pcap_setfilter(interface->ppcap, &bpfprogram) == -1) {
            fprintf(stderr, "%s\n", szProgram);
            fprintf(stderr, "%s\n", pcap_geterr(interface->ppcap));
        }
        pcap_freecode(&bpfprogram);
    }

    interface->selectable_fd = pcap_get_selectable_fd(interface->ppcap);
}
//resetting block buffer
void block_buffer_list_reset(block_buffer_t *block_buffer_list,
        size_t block_buffer_list_len, int block_buffer_len)
{
    int i;
    block_buffer_t *rb = block_buffer_list;

    for (i = 0; i < block_buffer_list_len; ++i) {
        rb->block_num = -1;

        int j;
        packet_buffer_t *p = rb->packet_buffer_list;
        for (j = 0;
                j < param_data_packets_per_block + param_fec_packets_per_block;
                ++j) {
            p->valid = 0;
            p->crc_correct = 0;
            p->len = 0;
            p++;
        }

        rb++;
    }
}

void process_payload_old(uint8_t *data, size_t data_len, int crc_correct,
        block_buffer_t *block_buffer_list, int adapter_no)
{
    wifi_packet_header_t *wph;
    int block_num;
    int packet_num;
    int i;
    static int max_block_num = -1;

    wph = (wifi_packet_header_t*) data;
    data += sizeof(wifi_packet_header_t);
    data_len -= sizeof(wifi_packet_header_t);

//  block_num = wph->packet_number
//      / (param_data_packets_per_block + param_fec_packets_per_block); //if aram_data_packets_per_block+param_fec_packets_per_block would be limited to powers of two, this could be replaced by a logical AND operation
    block_num = wph->block_number;
    //debug_print("adap %d rec %x blk %x crc %d len %d\n", adapter_no, wph->sequence_number, block_num, crc_correct, data_len);

    //we have received a block number that exceeds the currently seen ones -> we need to make room for this new block
    //or we have received a block_num that is several times smaller than the current window of buffers -> this indicated that either the window is too small or that the transmitter has been restarted
    int tx_restart = (block_num + 128 * param_block_buffers < max_block_num);
    if ((block_num > max_block_num || tx_restart) && crc_correct) {
        if (tx_restart) {
            rx_status->tx_restart_cnt++;

            fprintf(
            stderr,
                    "\033[1;1H *** ERROR: TX re-start detected ***                                                \n");

            block_buffer_list_reset(block_buffer_list, param_block_buffers,
                    param_data_packets_per_block + param_fec_packets_per_block);
        }

        //first, find the minimum block num in the buffers list. this will be the block that we replace
        int min_block_num = INT_MAX;
        int min_block_num_idx;
        for (i = 0; i < param_block_buffers; ++i) {
            if (block_buffer_list[i].block_num < min_block_num) {
                min_block_num = block_buffer_list[i].block_num;
                min_block_num_idx = i;
            }
        }

        //debug_print("removing block %x at index %i for block %x\n", min_block_num, min_block_num_idx, block_num);

        packet_buffer_t *packet_buffer_list =
                block_buffer_list[min_block_num_idx].packet_buffer_list;
        int last_block_num = block_buffer_list[min_block_num_idx].block_num;

        if (last_block_num != -1) {
            rx_status->received_block_cnt++;

            //we have both pointers to the packet buffers (to get information about crc and vadility) and raw data pointers for fec_decode
            packet_buffer_t *data_pkgs[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            packet_buffer_t *fec_pkgs[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            uint8_t *data_blocks[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            uint8_t *fec_blocks[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            int datas_missing = 0, datas_corrupt = 0, fecs_missing = 0,
                    fecs_corrupt = 0;
            int di = 0, fi = 0;

            //first, split the received packets into DATA a FEC packets and count the damaged packets
            i = 0;
            while (di < param_data_packets_per_block || fi
                    < param_fec_packets_per_block) {
                if (di < param_data_packets_per_block) {
                    data_pkgs[di] = packet_buffer_list + i++;
                    data_blocks[di] = data_pkgs[di]->data;
                    if (!data_pkgs[di]->valid)
                        datas_missing++;

// do not check for corrupted data packets as these are not forwarded from the kernel anyway
//                    if(data_pkgs[di]->valid && !data_pkgs[di]->crc_correct)
//                        datas_corrupt++;
                    di++;
                }

                if (fi < param_fec_packets_per_block) {
                    fec_pkgs[fi] = packet_buffer_list + i++;
                    if (!fec_pkgs[fi]->valid)
                        fecs_missing++;
// do not check for corrupted fec packets as these are not forwarded from the kernel anyway
//                    if(fec_pkgs[fi]->valid && !fec_pkgs[fi]->crc_correct)
//                        fecs_corrupt++;

                    fi++;
                }
            }

//            const int good_fecs_c = param_fec_packets_per_block - fecs_missing - fecs_corrupt;
            const int good_fecs_c = param_fec_packets_per_block - fecs_missing;
            const int datas_missing_c = datas_missing;
            const int datas_corrupt_c = datas_corrupt;
            const int fecs_missing_c = fecs_missing;
            const int fecs_corrupt_c = fecs_corrupt;

            int good_fecs = good_fecs_c;
            //the following three fields are infos for fec_decode
            unsigned int fec_block_nos[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            unsigned int erased_blocks[MAX_DATA_OR_FEC_PACKETS_PER_BLOCK];
            unsigned int nr_fec_blocks = 0;

#if DEBUG
            if(datas_missing_c + datas_corrupt_c > good_fecs_c)
            {
                int x;

                for(x=0;x<param_data_packets_per_block; ++x)
                {
                    if(data_pkgs[x]->valid)
                    {
                        if(data_pkgs[x]->crc_correct)
                        fprintf(stderr, "v");
                        else
                        fprintf(stderr, "c");
                    }
                    else
                    fprintf(stderr, "m");
                }

                fprintf(stderr, " ");

                for(x=0;x<param_fec_packets_per_block; ++x)
                {
                    if(fec_pkgs[x]->valid)
                    {
                        if(fec_pkgs[x]->crc_correct)
                        fprintf(stderr, "v");
                        else
                        fprintf(stderr, "c");
                    }
                    else
                    fprintf(stderr, "m");
                }

                fprintf(stderr, "\n");
            }
#endif

            fi = 0;
            di = 0;

            //look for missing DATA and replace them with good FECs
            while (di < param_data_packets_per_block && fi
                    < param_fec_packets_per_block) {
                //if this data is fine we go to the next
                if (data_pkgs[di]->valid && data_pkgs[di]->crc_correct) {
                    di++;
                    continue;
                }

                //if this DATA is corrupt and there are less good fecs than missing datas we cannot do anything for this data
                if (data_pkgs[di]->valid && !data_pkgs[di]->crc_correct
                    && good_fecs <= datas_missing) {
                    di++;
                    continue;
                }

                //if this FEC is not received we go on to the next
                if (!fec_pkgs[fi]->valid) {
                    fi++;
                    continue;
                }

                //if this FEC is corrupted and there are more lost packages than good fecs we should replace this DATA even with this corrupted FEC
                if (!fec_pkgs[fi]->crc_correct && datas_missing > good_fecs) {
                    fi++;
                    continue;
                }

                if (!data_pkgs[di]->valid)
                    datas_missing--;
                else if (!data_pkgs[di]->crc_correct)
                    datas_corrupt--;

                if (fec_pkgs[fi]->crc_correct)
                    good_fecs--;

                //at this point, data is invalid and fec is good -> replace data with fec
                erased_blocks[nr_fec_blocks] = di;
                fec_block_nos[nr_fec_blocks] = fi;
                fec_blocks[nr_fec_blocks] = fec_pkgs[fi]->data;
                di++;
                fi++;
                nr_fec_blocks++;
            }

            int reconstruction_failed = datas_missing_c + datas_corrupt_c
                    > good_fecs_c;

            if (reconstruction_failed) {
                //we did not have enough FEC packets to repair this block
                rx_status->damaged_block_cnt++;
                //fprintf(stderr, "Could not fully reconstruct block %x! Damage rate: %f (%d / %d blocks)\n", last_block_num, 1.0 * rx_status->damaged_block_cnt / rx_status->received_block_cnt, rx_status->damaged_block_cnt, rx_status->received_block_cnt);
                //debug_print("Data mis: %d\tData corr: %d\tFEC mis: %d\tFEC corr: %d\n", datas_missing_c, datas_corrupt_c, fecs_missing_c, fecs_corrupt_c);
            }

            //decode data and write it to STDOUT
            fec_decode((unsigned int) param_packet_length, data_blocks,
                    param_data_packets_per_block, fec_blocks, fec_block_nos,
                    erased_blocks, nr_fec_blocks);
            for (i = 0; i < param_data_packets_per_block; ++i) {
                payload_header_t *ph = (payload_header_t*) data_blocks[i];

                if (!reconstruction_failed || data_pkgs[i]->valid) {
                    //if reconstruction did fail, the data_length value is undefined. better limit it to some sensible value
                    if (ph->actual_length > param_packet_length)
                        ph->actual_length = param_packet_length;

                    write(STDOUT_FILENO,
                            data_blocks[i] + sizeof(payload_header_t),
                            ph->actual_length);
                    fflush(stdout);
                }
            }

            //reset buffers
            for (i = 0;
                    i < param_data_packets_per_block + param_fec_packets_per_block;
                    ++i) {
                packet_buffer_t *p = packet_buffer_list + i;
                p->valid = 0;
                p->crc_correct = 0;
                p->len = 0;
            }
        }

        block_buffer_list[min_block_num_idx].block_num = block_num;
        max_block_num = block_num;
    }

    //find the buffer into which we have to write this packet
    block_buffer_t *rbb = block_buffer_list;
    for (i = 0; i < param_block_buffers; ++i) {
        if (rbb->block_num == block_num) {
            break;
        }
        rbb++;
    }

    //check if we have actually found the corresponding block. this could not be the case due to a corrupt packet
    if (i != param_block_buffers) {
        packet_buffer_t *packet_buffer_list = rbb->packet_buffer_list;
        packet_num = wph->packet_number
                % (param_data_packets_per_block + param_fec_packets_per_block); //if retr_block_size would be limited to powers of two, this could be replace by a locical and operation

        //only overwrite packets where the checksum is not yet correct. otherwise the packets are already received correctly
        if (packet_buffer_list[packet_num].crc_correct == 0) {
            memcpy(packet_buffer_list[packet_num].data, data, data_len);
            packet_buffer_list[packet_num].len = data_len;
            packet_buffer_list[packet_num].valid = 1;
            packet_buffer_list[packet_num].crc_correct = crc_correct;
        }
    }

}
//TX received and reconstructed data to standard output
void tx_block(block_buffer_t * curr_buff, uint8_t force, int * done_blocks)
{
    uint8_t i;
    //if we have enough data + FEC packets output to stdout
    if ((curr_buff->fec_pkts_cnt + curr_buff->data_pkts_cnt) >= curr_buff->payload_hdr.num_data_blocks) {
        //updating already processed block counter
        rx_status->received_block_cnt++;
        //if we have all data packets received without corruptions
        if (curr_buff->data_pkts_cnt == curr_buff->payload_hdr.num_data_blocks) {
            //transmitting all data packets
            for (i = 0; i < curr_buff->data_pkts_cnt; ++i) {
                //transmit if only were not already transmitted
                if (!curr_buff->packet_buffer_list[i].tx_done) {
                    //out packet
                    write(STDOUT_FILENO, curr_buff->packet_buffer_list[i].data,
                            curr_buff->packet_buffer_list[i].len);
                }
                //Resetting packet buffer flags
                curr_buff->packet_buffer_list[i].tx_done = 0;
                curr_buff->packet_buffer_list[i].valid = 0;
                curr_buff->packet_buffer_list[i].crc_correct = 0;
            }
            //Resetting packet buffer flags
            for (; i < MAX_PACKETS_PER_BLOCK; ++i) {
                curr_buff->packet_buffer_list[i].tx_done = 0;
                curr_buff->packet_buffer_list[i].valid = 0;
                curr_buff->packet_buffer_list[i].crc_correct = 0;
            }
        //we received not all data packets but enough FEC packets to reconstruct
        } else {
            uint8_t *data_blocks[MAX_PACKETS_PER_BLOCK];
            uint8_t *fec_blocks[MAX_PACKETS_PER_BLOCK];
            //the following three fields are infos for fec_decode
            unsigned int fec_block_nos[MAX_PACKETS_PER_BLOCK];
            unsigned int erased_block_nos[MAX_PACKETS_PER_BLOCK];
            uint8_t j = 0;
            //collecting all missing data packets indexes
            for (i = 0; i < curr_buff->payload_hdr.num_data_blocks; ++i) {
                data_blocks[i] = curr_buff->packet_buffer_list[i].data;
                if (!curr_buff->packet_buffer_list[i].valid) {
                    erased_block_nos[j++] = i;
                }
                //Resetting packet buffer flags in a side-car
                curr_buff->packet_buffer_list[i].tx_done = 0;
                curr_buff->packet_buffer_list[i].valid = 0;
                curr_buff->packet_buffer_list[i].crc_correct = 0;
            }
            uint8_t nr_fec_blocks = j;
            j = 0;
            //collecting all valid FEC packets
            for (i = curr_buff->payload_hdr.num_data_blocks;
                    i < (curr_buff->payload_hdr.num_data_blocks + curr_buff->payload_hdr.num_fecs_blocks);
                    ++i) {
                if (++j == nr_fec_blocks)
                    break;
                if (!curr_buff->packet_buffer_list[i].valid) {
                    fec_block_nos[j] = i;
                    fec_blocks[j] = curr_buff->packet_buffer_list[i].data;
                }
                //Resetting packet buffer flags in a side-car
                curr_buff->packet_buffer_list[i].tx_done = 0;
                curr_buff->packet_buffer_list[i].valid = 0;
                curr_buff->packet_buffer_list[i].crc_correct = 0;
            }
            //Resetting packet buffer flags
            for (; i < MAX_PACKETS_PER_BLOCK; ++i) {
                curr_buff->packet_buffer_list[i].tx_done = 0;
                curr_buff->packet_buffer_list[i].valid = 0;
                curr_buff->packet_buffer_list[i].crc_correct = 0;
            }
            //since we got all valid, missed data packets as well as valid FEC frames
            //decode data
            fec_decode(
                    (unsigned int) curr_buff->payload_hdr.nominal_packet_length,
                    data_blocks, curr_buff->payload_hdr.num_data_blocks,
                    fec_blocks, fec_block_nos, erased_block_nos, nr_fec_blocks);
            //and write it to STDOUT
            for (i = curr_buff->curr_pkt_num;
                    i < curr_buff->payload_hdr.num_data_blocks; ++i) {
                if (!curr_buff->packet_buffer_list[i].tx_done) {
                    //output packet
                    write(STDOUT_FILENO, curr_buff->packet_buffer_list[i].data,
                            curr_buff->packet_buffer_list[i].len);

                }
            }
        }
        //saving a back-log of already processed blocks
        //pushing out only the oldest previous block number
        if (done_blocks[0] < done_blocks[1])
            done_blocks[0] = curr_buff->block_num;
        else if (done_blocks[1] < done_blocks[0])
            done_blocks[1] = curr_buff->block_num;
        else
            done_blocks[0] = curr_buff->block_num;
        curr_buff->block_num = -1;
        curr_buff->curr_pkt_num = 0;
        curr_buff->data_pkts_cnt = 0;
        curr_buff->fec_pkts_cnt = 0;
    //if we are forcing to flush already accumulated data regardless how many data frames were lost of FEC frames safely received
    } else if (force) {
        //outputting all present data frames
        for (i = 0; i < curr_buff->payload_hdr.num_data_blocks; ++i) {
            //except those already transmitted
            if (!curr_buff->packet_buffer_list[i].tx_done
#ifdef CLEAN_OUT
            && curr_buff->packet_buffer_list[i].valid
#endif
            ) {
                //out packet
                write(STDOUT_FILENO, curr_buff->packet_buffer_list[i].data,
                        curr_buff->packet_buffer_list[i].len);

            }
        }
        //Resetting packet buffer flags
        for (; i < MAX_PACKETS_PER_BLOCK; ++i) {
            curr_buff->packet_buffer_list[i].tx_done = 0;
            curr_buff->packet_buffer_list[i].valid = 0;
            curr_buff->packet_buffer_list[i].crc_correct = 0;
        }
        //collecting damaged block statistics
        rx_status->damaged_block_cnt++;
        //saving a back-log of already processed blocks
        //pushing out only the oldest previous block number
        if (done_blocks[0] < done_blocks[1])
            done_blocks[0] = curr_buff->block_num;
        else if (done_blocks[1] < done_blocks[0])
            done_blocks[1] = curr_buff->block_num;
        else
            done_blocks[0] = curr_buff->block_num;
        curr_buff->block_num = -1;
        curr_buff->curr_pkt_num = 0;
        curr_buff->data_pkts_cnt = 0;
        curr_buff->fec_pkts_cnt = 0;
    }

}
//process packet payload
void process_payload(uint8_t *data, size_t data_len, int crc_correct,
        block_buffer_t *block_buffer_list, uint8_t num_buffers)
{
    wifi_packet_header_t *wph;
    payload_header_t * plh;

    unsigned int block_num;
    unsigned int packet_num;
    unsigned int i;
    //initializing processed blocks back-log
    static int prev_done_blocks[2] = {-1, -1};

    //maping packet headers structures
    wph = (wifi_packet_header_t*) data;
    data += sizeof(wifi_packet_header_t);
    data_len -= sizeof(wifi_packet_header_t);
    plh = (payload_header_t *) data;
    data += sizeof(payload_header_t);
    data_len -= sizeof(payload_header_t);

//  block_num = wph->packet_number
//      / (param_data_packets_per_block + param_fec_packets_per_block); //if aram_data_packets_per_block+param_fec_packets_per_block would be limited to powers of two, this could be replaced by a logical AND operation
    block_num = wph->block_number;
    //debug_print("adap %d rec %x blk %x crc %d len %d\n", adapter_no, wph->sequence_number, block_num, crc_correct, data_len);

    packet_num = wph->packet_number;
    block_buffer_t * curr_buff = 0;
    uint8_t other_buff_idx = 0;

    //if packet came from already transmitted block skip it, we save last 2 block numbers
    //anything else should be treated as transmission reset
    if(block_num == prev_done_blocks[0] || block_num == prev_done_blocks[1])
        return;
    //searching for the block for received packet
    if (block_buffer_list[0].block_num == block_num) {
        curr_buff = &block_buffer_list[0];
        other_buff_idx = 1;
    } else if (block_buffer_list[1].block_num == block_num) {
        curr_buff = &block_buffer_list[1];
        other_buff_idx = 0;
    //if received packet is from unknown block
    } else if (((block_num > block_buffer_list[1].block_num)
            && (block_num > block_buffer_list[0].block_num))
               || ((block_num > block_buffer_list[1].block_num) && (block_num
                       < block_buffer_list[0].block_num))
               || ((block_num > block_buffer_list[0].block_num) && (block_num
                       < block_buffer_list[1].block_num))) {
        //we received packet from a block either in between of the two blocks being processed,
        //or the packet from a block ahead of all two blocks being processed, we flush the oldest block
        if (block_buffer_list[0].block_num < block_buffer_list[1].block_num) {
            //flush the oldest block if it has some data, and replace it with the newly received packet block
            curr_buff = &block_buffer_list[0];
            other_buff_idx = 1;
            if (block_buffer_list[0].block_num != -1) {
                //spit out block_buffer_list[0]
                tx_block(curr_buff, 1, prev_done_blocks);
            }
        } else {
            //flush the oldest block if it has some data, and replace it with the newly received packet block
            curr_buff = &block_buffer_list[1];
            other_buff_idx = 0;
            if (block_buffer_list[1].block_num != -1) {
                //spit out block_buffer_list[1]
                tx_block(curr_buff, 1, prev_done_blocks);
            }
        }
    //most likely transmission restart has occurred, we received block which is earlier than both already being processed
    //flush both block, pick one on them as a placeholder for a new packet afterwards
    } else if ((block_num < block_buffer_list[1].block_num)
            && (block_num < block_buffer_list[0].block_num)) {
        curr_buff = &block_buffer_list[0];
        other_buff_idx = 1;
        //flush the block if it has any received data in it
        if (block_buffer_list[0].block_num) {
            //spit out block_buffer_list[0]
            tx_block(curr_buff, 1, prev_done_blocks);
        }
        //flush the block if it has any received data in it
        if (block_buffer_list[1].block_num != -1) {
            //spit out block_buffer_list[1]
            tx_block(&block_buffer_list[1], 1, prev_done_blocks);
        }
        //possible transmission restart counter update
        rx_status->tx_restart_cnt++;
    }
    //updating currently processing block parameters
    curr_buff->block_num = block_num;
    //curr_buff->payload_hdr.data_length = plh->data_length;
    curr_buff->payload_hdr.nominal_packet_length = plh->nominal_packet_length;
    curr_buff->payload_hdr.num_data_blocks = plh->num_data_blocks;
    curr_buff->payload_hdr.num_fecs_blocks = plh->num_fecs_blocks;
    //data and FEC packet counters update
    if (wph->fec_taint)
        curr_buff->fec_pkts_cnt++;
    else
        curr_buff->data_pkts_cnt++;
    //setting packet buffer data pointer to the newly received data
    curr_buff->packet_buffer_list[packet_num].data = data;
    //updating current packet buffer element flags
    curr_buff->packet_buffer_list[packet_num].valid = 1;
    curr_buff->packet_buffer_list[packet_num].len = plh->actual_length;
    curr_buff->packet_buffer_list[packet_num].tx_done = 0;
    curr_buff->packet_buffer_list[packet_num].crc_correct =
            (wph->fec_taint) ? 1 : 2;
    //lag reduction addition, spit out any correctly received data packet arrived in a sequence with previous ones
    if ((packet_num == curr_buff->curr_pkt_num) && !wph->fec_taint) {
        //only if either second block buffer is empty, or second buffer number is newer (higher) than current one.
        //This keeps packets ordered prohibiting packets from newer block to interleave with packets with older block
        if ((block_buffer_list[other_buff_idx].block_num == -1) || (block_buffer_list[other_buff_idx].block_num
                > curr_buff->block_num)) {
            //out packet
            write(STDOUT_FILENO, curr_buff->packet_buffer_list[packet_num].data,
                    curr_buff->packet_buffer_list[packet_num].len);
            curr_buff->packet_buffer_list[packet_num].tx_done = 1;
            curr_buff->curr_pkt_num++;
        }
    }
    //try to output the whole block, if there is not enough packets data and/or FEC the function just does nothing
    tx_block(curr_buff, 0, prev_done_blocks);

}
//Low level packet processing before payload processing
void process_packet(monitor_interface_t *interface, int adapter_no,
        block_buffer_t *block_buffer_list, uint8_t num_buffers,
        struct pkt_buff_t * pbuff)
{
    struct pcap_pkthdr * ppcapPacketHeader = NULL;
    struct ieee80211_radiotap_iterator rti;
    PENUMBRA_RADIOTAP_DATA prd;
    u8 payloadBuffer[MAX_PACKET_LENGTH];
    u8 *pu8Payload = payloadBuffer;
    int bytes;
    int n;
    int retval;
    int u16HeaderLen;

    // receive raw packet from PCAP handle to the interface
    retval = pcap_next_ex(interface->ppcap, &ppcapPacketHeader,
            (const u_char**) &pu8Payload);

    if (retval < 0) {
        if (strcmp("The interface went down", pcap_geterr(interface->ppcap)) == 0) {
            fprintf(stderr,
                    "\033[1;1H ERROR: Interface went down, wifi card removed");
            exit(9);
        } else {
            fprintf(stderr, "\033[1;1H%s\n", pcap_geterr(interface->ppcap));
            //fprintf(stderr, "%s\n", pcap_geterr(interface->ppcap));
            exit(2);
        }
    }

    if (retval != 1)
        return;
    //packet basic sanity checks
    u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

    if (ppcapPacketHeader->len <= (u16HeaderLen + interface->n80211HeaderLength))
        return;

    bytes = ppcapPacketHeader->len - (u16HeaderLen
            + interface->n80211HeaderLength);
    //reading Radio TAP data (low level WiFi data)
    if (ieee80211_radiotap_iterator_init(&rti,
                (struct ieee80211_radiotap_header *) pu8Payload,
                ppcapPacketHeader->len)
        < 0)
        return;
    //filling WiFi RF statistics
    while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {

        switch (rti.this_arg_index) {
            case IEEE80211_RADIOTAP_RATE:
                prd.m_nRate = (*rti.this_arg);
                break;

            case IEEE80211_RADIOTAP_CHANNEL:
                prd.m_nChannel = le16_to_cpu(*((u16 * )rti.this_arg));
                prd.m_nChannelFlags = le16_to_cpu(
                        *((u16 * )(rti.this_arg + 2)));
                break;

            case IEEE80211_RADIOTAP_ANTENNA:
                prd.m_nAntenna = (*rti.this_arg) + 1;
                break;

            case IEEE80211_RADIOTAP_FLAGS:
                prd.m_nRadiotapFlags = *rti.this_arg;
                break;

            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                rx_status->adapter[adapter_no].current_signal_dbm =
                        (int8_t) (*rti.this_arg);
                break;
        }
    }
    //moving payload pointer forward to the actual payload
    pu8Payload += u16HeaderLen + interface->n80211HeaderLength;

    if (prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_FCS)
        bytes -= 4;

// skip radiotap checksum check to free up some CPU (bad packets are not forwarded to userspace anyway)
//        int checksum_correct = (prd.m_nRadiotapFlags & 0x40) == 0;
    int checksum_correct = 1;

//		if(!checksum_correct)
//			rx_status->adapter[adapter_no].wrong_crc_cnt++;
    //low-level packet counter
    rx_status->adapter[adapter_no].received_packet_cnt++;

//		if(rx_status->adapter[adapter_no].received_packet_cnt % 1024 == 0) {
//			fprintf(stderr, "Signal (card %d): %ddBm\n", adapter_no, rx_status->adapter[adapter_no].current_signal_dbm);
//		}

    rx_status->last_update = time(NULL);
    //waiting on circular packet buffer to become free
    uint16_t chk_idx = (pbuff->rx_idx + 1) % (pbuff->pkt_num);
    while (chk_idx == pbuff->tx_idx) {
        sched_yield();
    }
    //filling packet buffer data length
    pbuff->packets[pbuff->rx_idx].read_pkt_len = bytes;
    //since payload buffer provided by PCAP is not saved between PCAP reads, we need to copy it to the packet circular buffer
    memmove(&pbuff->packets[pbuff->rx_idx].data, pu8Payload, bytes);
    pbuff->rx_idx = chk_idx;
}
//statistics shared memory init
void status_memory_init(wifibroadcast_rx_status_t *s)
{
    s->received_block_cnt = 0;
    s->damaged_block_cnt = 0;
    s->tx_restart_cnt = 0;
    s->wifi_adapter_cnt = 0;

    int i;
    for (i = 0; i < MAX_PENUMBRA_INTERFACES; ++i) {
        s->adapter[i].received_packet_cnt = 0;
        s->adapter[i].wrong_crc_cnt = 0;
        s->adapter[i].current_signal_dbm = 0;
    }
}
//statistics shared memory creation
wifibroadcast_rx_status_t *
status_memory_open(void)
{
    static char buf[128];
    int fd;
    //opening shared memory
    sprintf(buf, "/wifibroadcast_rx_status_%d", param_port);
    fd = shm_open(buf, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);

    if (fd < 0) {
        perror("shm_open");
        exit(1);
    }
    //shared memory GC assignment
    on_exit(gc_shm, buf);
    if (ftruncate(fd, sizeof(wifibroadcast_rx_status_t)) == -1) {
        perror("ftruncate");
        exit(1);
    }
    //mapping shared memory to the process adress space
    void *retval = mmap(NULL, sizeof(wifibroadcast_rx_status_t),
                        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (retval == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    //mapped shared memory GC assignment
    on_exit(gc_mmap, retval);
    wifibroadcast_rx_status_t *tretval = (wifibroadcast_rx_status_t*) retval;
    status_memory_init(tretval);

    return tretval;

}

//processing thread main function
static void * thread_proc(void *arg)
{
    rx_data_t * prx_data = (rx_data_t *) arg;
    while (1) {
        //setting thread cancellation point
        pthread_testcancel();
        //if Tx circular buffer index catches Rx index just yield
        if (prx_data->pkt_buffer.rx_idx == prx_data->pkt_buffer.tx_idx) {
            sched_yield();
            continue;
        }
        //process packets otherwise
        process_payload(
                &prx_data->pkt_buffer.packets[prx_data->pkt_buffer.tx_idx].data,
                prx_data->pkt_buffer.packets[prx_data->pkt_buffer.tx_idx].read_pkt_len,
                prx_data->blk_buffer, prx_data->blk_num);
        prx_data->pkt_buffer.tx_idx = (prx_data->pkt_buffer.tx_idx + 1)
                % (prx_data->pkt_buffer.pkt_num);
    }
    pthread_exit(arg);
    return arg;
}
int main(int argc, char *argv[])
{
    monitor_interface_t interfaces[MAX_PENUMBRA_INTERFACES];
    int num_interfaces = 0;
    int i;

    rx_data_t rx_data;
    //disabling stdout buffering
    setvbuf(stdout, NULL, _IONBF, 0);
    //reading command line parameters
    while (1) {
        int nOptionIndex;
        static const struct option optiona[] = { { "help", no_argument,
                &flagHelp, 1 }, { 0, 0, 0, 0 } };
//      int c = getopt_long (argc, argv, "hp:b:d:r:f:", optiona, &nOptionIndex);
        int c = getopt_long(argc, argv, "hp:", optiona, &nOptionIndex);

        if (c == -1)
            break;
        switch (c) {
            case 0: // long option
                break;

            case 'h': // help
                usage();

            case 'p': //port
                param_port = atoi(optarg);
                break;

//	case 'b':
//	  param_data_packets_per_block = atoi (optarg);
//	  break;
//
//	case 'r':
//	  param_fec_packets_per_block = atoi (optarg);
//	  break;
//
//	case 'd':
//	  param_block_buffers = atoi (optarg);
//	  break;
//
//	case 'f': // MTU
//	  param_packet_length = atoi (optarg);
//	  break;

            default:
                fprintf(stderr, "unknown switch %c\n", c);
                usage();
                break;
        }
    }

    if (optind >= argc)
        usage();

    if (param_packet_length > MAX_USER_PACKET_LENGTH) {
        printf(
                "Packet length is limited to %d bytes (you requested %d bytes)\n",
                MAX_USER_PACKET_LENGTH, param_packet_length);
        return (1);
    }
    //initializing FEC decoder
    fec_init();
    //opening all supplied interfaces
    int x = optind;
    while (x < argc && num_interfaces < MAX_PENUMBRA_INTERFACES) {
        open_and_configure_interface(argv[x], param_port,
                interfaces + num_interfaces);
        ++num_interfaces;
        ++x;
    }
    //allocating and initializing all Rx required buffers
    //block buffers contain both the block_num as well as packet buffers for a block.
    rx_data.blk_num = param_block_buffers;
    rx_data.blk_buffer = (block_buffer_t *) malloc(
            sizeof(block_buffer_t) * param_block_buffers);
    for (i = 0; i < rx_data.blk_num; ++i) {
        rx_data.blk_buffer[i].block_num = -1;
        rx_data.blk_buffer[i].curr_pkt_num = 0;
        rx_data.blk_buffer[i].data_pkts_cnt = 0;
        rx_data.blk_buffer[i].fec_pkts_cnt = 0;
        //we are not allocating actual data buffers inside packet structures,
        //since we are using one continuous circular packet buffer, which we use pointers to later on
        rx_data.blk_buffer[i].packet_buffer_list = lib_alloc_packet_buffer_list(
        MAX_PACKETS_PER_BLOCK, 0);
    }

    rx_data.pkt_buffer.rx_idx = 0;
    rx_data.pkt_buffer.tx_idx = 0;
    rx_data.pkt_buffer.pkt_num = MAX_PACKETS_PER_BLOCK * MAX_BLOCKS;
    //allocating actual continuous packets buffer for MAX_BLOCKS, it should accomodate any DATA/FEC packets numbers combinations
    rx_data.pkt_buffer.packets = (struct pkt_struct_rx_t *) malloc(
            sizeof(struct packets_t) * rx_data.pkt_buffer.pkt_num);
    on_exit(gc_rx_data, &rx_data);
    rx_status = status_memory_open();
    rx_status->wifi_adapter_cnt = num_interfaces;

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
    if (pthread_create(&proc_thread, &pattr, thread_proc, &rx_data)) {
        perror("Failed to create processing thread, aborting...\n");
        return 1;
    }
    //garbage collector push
    on_exit(gc_pthr, &proc_thread);
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
    struct epoll_event eearr[MAX_PENUMBRA_INTERFACES];
    for (i = 0; i < num_interfaces; ++i) {
        eearr[i].events = EPOLLIN;
        eearr[i].data.u32 = i;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, interfaces[i].selectable_fd,
                    &eearr[i])
            == -1) {
            perror("Failed to add FIFO fd to epoll, aborting\n");
            return 1;
        }

    }
#endif

    for (;;) {
        fd_set readset;
        struct timeval to;

        to.tv_sec = 0;
        to.tv_usec = 1e5;
#ifdef SELECT_EN
        FD_ZERO(&readset);
        for (i = 0; i < num_interfaces; ++i)
        FD_SET(interfaces[i].selectable_fd, &readset);

        int n = select (30, &readset, NULL, NULL, &to);

        for (i = 0; i < num_interfaces; ++i)
        {
            if (n == 0)
            break;
            if (FD_ISSET(interfaces[i].selectable_fd, &readset))
            {
                process_packet (interfaces + i, i, rx_data.blk_buffer, rx_data.blk_num);
            }
        }
#else
        int nfds;
        //waiting for packets to arrive
        do {
            nfds = epoll_wait(epfd, eearr, 8, -1);
        } while (nfds < 0 && errno == EINTR);
        if (nfds < 0) {
            perror("epoll_wait failed, aborting...\n");
            return 1;
        }
        for (i = 0; i < nfds; ++i) {
            //processing Raw packets and putting payload into the circular packet buffer in the end
            process_packet(interfaces + eearr[i].data.u32, eearr[i].data.u32,
                    rx_data.blk_buffer, rx_data.blk_num);
        }
#endif
    }

    return (0);
}
