/*
 * Argon2 source code package
 *
 * Written by Daniel Dinu and Dmitry Khovratovich, 2015
 *
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with
 * this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include <immintrin.h>

#include "argon2.h"
#include "cores.h"
#include "opt.h"

#include "blake2/blake2.h"
#include "blake2/blamka-round-opt.h"

void fill_block(__m128i *state, __m128i const *ref_block, __m128i const *next_block) {
    
    __m128i block_XY[ARGON2_QWORDS_IN_BLOCK] __attribute__ ((aligned (16)));
    uint32_t i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        block_XY[i] = state[i] = _mm_xor_si128(
            state[i], _mm_load_si128(&ref_block[i]));
    }

BLAKE2_ROUND(state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);
BLAKE2_ROUND(state[8], state[9], state[10], state[11], state[12], state[13], state[14], state[15]);
BLAKE2_ROUND(state[16], state[17], state[18], state[19], state[20], state[21], state[22], state[23]);
BLAKE2_ROUND(state[24], state[25], state[26], state[27], state[28], state[29], state[30], state[31]);
BLAKE2_ROUND(state[32], state[33], state[34], state[35], state[36], state[37], state[38], state[39]);
BLAKE2_ROUND(state[40], state[41], state[42], state[43], state[44], state[45], state[46], state[47]);
BLAKE2_ROUND(state[48], state[49], state[50], state[51], state[52], state[53], state[54], state[55]);
BLAKE2_ROUND(state[56], state[57], state[58], state[59], state[60], state[61], state[62], state[63]);
    /*for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                     state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                     state[8 * i + 6], state[8 * i + 7]);
    }*/

BLAKE2_ROUND(state[0], state[8], state[16], state[24], state[32], state[40], state[48], state[56]);
BLAKE2_ROUND(state[1], state[9], state[17], state[25], state[33], state[41], state[49], state[57]);
BLAKE2_ROUND(state[2], state[10], state[18], state[26], state[34], state[42], state[50], state[58]);
BLAKE2_ROUND(state[3], state[11], state[19], state[27], state[35], state[43], state[51], state[59]);
BLAKE2_ROUND(state[4], state[12], state[20], state[28], state[36], state[44], state[52], state[60]);
BLAKE2_ROUND(state[5], state[13], state[21], state[29], state[37], state[45], state[53], state[61]);
BLAKE2_ROUND(state[6], state[14], state[22], state[30], state[38], state[46], state[54], state[62]);
BLAKE2_ROUND(state[7], state[15], state[23], state[31], state[39], state[47], state[55], state[63]);
    /*for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                     state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                     state[8 * 6 + i], state[8 * 7 + i]);
    }*/

    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        state[i] = _mm_xor_si128(state[i], block_XY[i]);
        _mm_storeu_si128(&next_block[i], state[i]);
    }
}

void fill_block_from_zero(__m128i const *ref_block, __m128i const *next_block) {
  __m128i state[ARGON2_QWORDS_IN_BLOCK] __attribute__ ((aligned (16)));
  
  uint8_t i = 0;
  for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) 
    state[i] = _mm_load_si128(&ref_block[i]);

    /*for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                     state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                     state[8 * i + 6], state[8 * i + 7]);
    }*/
    /*for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                     state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                     state[8 * 6 + i], state[8 * 7 + i]);
    }*/
BLAKE2_ROUND(state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);
BLAKE2_ROUND(state[8], state[9], state[10], state[11], state[12], state[13], state[14], state[15]);
BLAKE2_ROUND(state[16], state[17], state[18], state[19], state[20], state[21], state[22], state[23]);
BLAKE2_ROUND(state[24], state[25], state[26], state[27], state[28], state[29], state[30], state[31]);
BLAKE2_ROUND(state[32], state[33], state[34], state[35], state[36], state[37], state[38], state[39]);
BLAKE2_ROUND(state[40], state[41], state[42], state[43], state[44], state[45], state[46], state[47]);
BLAKE2_ROUND(state[48], state[49], state[50], state[51], state[52], state[53], state[54], state[55]);
BLAKE2_ROUND(state[56], state[57], state[58], state[59], state[60], state[61], state[62], state[63]);

BLAKE2_ROUND(state[0], state[8], state[16], state[24], state[32], state[40], state[48], state[56]);
BLAKE2_ROUND(state[1], state[9], state[17], state[25], state[33], state[41], state[49], state[57]);
BLAKE2_ROUND(state[2], state[10], state[18], state[26], state[34], state[42], state[50], state[58]);
BLAKE2_ROUND(state[3], state[11], state[19], state[27], state[35], state[43], state[51], state[59]);
BLAKE2_ROUND(state[4], state[12], state[20], state[28], state[36], state[44], state[52], state[60]);
BLAKE2_ROUND(state[5], state[13], state[21], state[29], state[37], state[45], state[53], state[61]);
BLAKE2_ROUND(state[6], state[14], state[22], state[30], state[38], state[46], state[54], state[62]);
BLAKE2_ROUND(state[7], state[15], state[23], state[31], state[39], state[47], state[55], state[63]);


/* Unrolling loops might not be the best idea. This might overload
   the instruction cache... */
   for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
     state[i] = _mm_xor_si128(state[i], _mm_load_si128(&ref_block[i]));
     _mm_store_si128(&next_block[i], state[i]);
   }
}




void generate_addresses(const argon2_instance_t *instance,
                        const argon2_position_t *position,
                        uint64_t *pseudo_rands) {
    block address_block, input_block;
    uint32_t i;

    init_block_value(&address_block, 0);
    init_block_value(&input_block, 0);

    input_block.v[0] = position->pass;
    input_block.v[1] = position->lane;
    input_block.v[2] = position->slice;
    input_block.v[3] = 16;
    input_block.v[4] = 2;
    input_block.v[5] = instance->type;
    input_block.v[6]++;
    fill_block_from_zero((__m128i const *)&input_block.v, 
                         (__m128i const *)&address_block.v);
    fill_block_from_zero((__m128i const *)&address_block.v, 
                         (__m128i const *)&address_block.v);

    pseudo_rands[0] = address_block.v[0];
    pseudo_rands[1] = address_block.v[1];
    pseudo_rands[2] = address_block.v[2];
    pseudo_rands[3] = address_block.v[3];
}

void fill_segment(const argon2_instance_t *instance,
                  argon2_position_t position) {
    block *ref_block = NULL, *curr_block = NULL;
    uint64_t pseudo_rand, ref_index, ref_lane;
    uint32_t prev_offset, curr_offset;
    uint32_t starting_index, i;
    __m128i state[64];
    int data_independent_addressing = (instance->type == Argon2_i);

    /* Pseudo-random values that determine the reference block position */
    uint64_t *pseudo_rands = NULL;

    /*if (instance == NULL) {
        return;
    }*/

    pseudo_rands = (uint64_t *)malloc(/*sizeof(uint64_t) * 4*/32);

    /*if (pseudo_rands == NULL) {
        return;
    }*/

    if (data_independent_addressing) {
        generate_addresses(instance, &position, pseudo_rands);
    }

    starting_index = 0;

    if ((0 == position.pass) && (0 == position.slice)) {
        starting_index = 2; /* we have already generated the first two blocks */
    }

    /* Offset of the current block */
    curr_offset = position.lane * 16 +
                  position.slice * 4 + starting_index;

    if (0 == curr_offset % 16) {
        /* Last block in this lane */
        prev_offset = curr_offset + /*instance->lane_length - 1*/15;
    } else {
        /* Previous block */
        prev_offset = curr_offset - 1;
    }

    memcpy(state, ((instance->memory + prev_offset)->v), ARGON2_BLOCK_SIZE);

    for (i = starting_index; i < /*instance->segment_length*/4;
         ++i, ++curr_offset, ++prev_offset) {
        /*1.1 Rotating prev_offset if needed */
        if (curr_offset % /*instance->lane_length*/16 == 1) {
            prev_offset = curr_offset - 1;
        }

        /* 1.2 Computing the index of the reference block */
        /* 1.2.1 Taking pseudo-random value from the previous block */
        if (data_independent_addressing) {
            pseudo_rand = pseudo_rands[i];
        } else {
            pseudo_rand = instance->memory[prev_offset].v[0];
        }

        /* 1.2.2 Computing the lane of the reference block */

        /* 1.2.3 Computing the number of possible reference block within the
         * lane.
         */
        position.index = i;
        ref_index = index_alpha(instance, &position, pseudo_rand & 0xFFFFFFFF,1);

        /* 2 Creating a new block */
        ref_block = instance->memory + ref_index;
        curr_block = instance->memory + curr_offset;
        fill_block(state, (__m128i const *)ref_block->v, (__m128i const *)curr_block->v);
    }

    free(pseudo_rands);
}
