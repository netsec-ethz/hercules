#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "libscion_checksum.h"

/*
 * Calculate RFC1071 checksum of supplied data chunks. The use of a gather
 * mechanism means there's 0 copies required to calculate the checksum.
 * in: a struct containing the number of chunks, for every chunk a length and a
 *     pointer to its start.
 */
uint16_t checksum(chk_input *in) {
    int i;
    /* As the maximum packet size is 65535B, the 32-bit accumulator cannot overflow. */
    uint32_t sum = 0;

    // Iterate over the chunks
    for (i=0; i < in->idx; i++){
        int j = 0;
        int len = in->len[i];
        int len2 = len/2;
        uint16_t *ptr = (uint16_t *)(in->ptr[i]);
        if (len == 0) {
            continue;
        }
        for (; j < len2; j++) {
            sum += ptr[j];
        }
        // Add left-over byte, if any
        if (len % 2 != 0) {
            sum += in->ptr[i][len-1];
        }
    }
    // Fold 32-bit sum to 16 bits
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return ones-complement.
    // XXX(kormat): this value is in network-byte order.
    return ~sum;
}

/*
 * Helper function to initialize a chk_input struct for checksum.
 * total: number of input chunks.
 */
chk_input *init_chk_input(chk_input *input, int total){
    input->idx = 0;
    if (total > SCION_MAX_CHECKSUM_CHUNKS) {
    	return NULL;
    }
    input->total = total;
    return input;
}

/*
 * Helper function to populate a chk_input struct for checksum.
 * in: Pointer to the chk_input struct.
 * idx: Index of the current chunk.
 * ptr: Pointer to start of data chunk.
 * len: Length of data chunk.
 * return value: a pointer to the data following the current chunk.
 */
const uint8_t * chk_add_chunk(chk_input *in, const uint8_t *ptr, int len) {
    assert(in->idx < in->total);
    in->len[in->idx] = len;
    in->ptr[in->idx] = ptr;
    in->idx++;
    return ptr + len;
}

