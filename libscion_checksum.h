#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

#define SCION_MAX_CHECKSUM_CHUNKS 5

typedef struct {
    uint8_t idx;
    uint8_t total;
    uint16_t len[SCION_MAX_CHECKSUM_CHUNKS];
    const uint8_t *ptr[SCION_MAX_CHECKSUM_CHUNKS];
} chk_input;

uint16_t checksum(chk_input *in);
chk_input *init_chk_input(chk_input *input, int count);
void rm_chk_input(chk_input *in);
const uint8_t * chk_add_chunk(chk_input *in, const uint8_t *ptr, int len);

#endif
